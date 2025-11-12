# Reticulum License
#
# Copyright (c) 2016-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from RNS.Interfaces.Interface import Interface
import threading
import time
import os
import hashlib
import struct
import zlib
import RNS
from collections import deque

try:
    import boto3
    from botocore.client import Config
    from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
except ImportError:
    boto3 = None


class S3Interface(Interface):
    """
    S3-based interface for Reticulum networking stack.
    Provides asynchronous, store-and-forward communication using S3-compatible storage.

    Compatible with:
    - AWS S3
    - MinIO
    - Wasabi
    - DigitalOcean Spaces
    - Backblaze B2
    - Any S3-compatible storage

    Uses only standard S3 API calls - no dependency on AWS-specific services (SQS, SNS, Lambda).
    """

    # Default configuration
    DEFAULT_POLL_INTERVAL = 1  # seconds - optimized for faster message delivery
    DEFAULT_CLEANUP_INTERVAL = 3600  # 1 hour
    DEFAULT_RETENTION_PERIOD = 86400  # 24 hours
    DEFAULT_BATCH_SIZE = 50
    DEFAULT_MTU = 2000000 #5mb
    DEFAULT_BITRATE = 2000000  # 10 Mbps estimate - optimized for fast window expansion
    DEFAULT_IFAC_SIZE = 16  # Interface announce cache size

    # Batching configuration
    DEFAULT_BATCH_MAX_SIZE = 1500000  # ~1.5 MB
    DEFAULT_BATCH_MAX_DELAY = 0.8  # seconds
    BATCH_MAGIC = b"RXC2"  # Magic bytes to identify batched packets
    BATCH_FLAG_COMPRESSED = 0x01  # Flag indicating compressed batch

    # Packet types (from RNS.Packet)
    PACKET_TYPE_DATA = 0x00
    PACKET_TYPE_ANNOUNCE = 0x01
    PACKET_TYPE_LINKREQUEST = 0x02
    PACKET_TYPE_PROOF = 0x03

    # Security limits
    MAX_PACKETS_PER_BATCH = 1000  # DoS protection
    MAX_PACKET_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_PACKETS_PER_POLL = 500  # Prevent unbounded processing

    # Reconnection settings
    RECONNECT_WAIT = 15
    RECONNECT_MAX_TRIES = None
    RECONNECT_BACKOFF_MAX = 300  # 5 minutes max

    # S3 operation timeouts
    CONNECT_TIMEOUT = 30
    READ_TIMEOUT = 60

    # MTU configuration
    AUTOCONFIGURE_MTU = False
    FIXED_MTU = True  # S3 has fixed MTU, enable link MTU discovery

    def __init__(self, owner, configuration):
        if boto3 is None:
            raise ImportError("boto3 library is required for S3Interface. Install with: pip install boto3")

        super().__init__()

        c = Interface.get_config_obj(configuration)

        # Basic configuration
        self.name = c["name"]
        self.owner = owner
        self.online = False
        self.detached = False
        self.reconnecting = False
        self.never_connected = True

        # S3 connection parameters
        self.s3_endpoint = c.get("s3_endpoint", "https://s3.amazonaws.com")
        self.s3_region = c.get("s3_region", "us-east-1")
        self.s3_bucket = c["s3_bucket"]
        self.s3_access_key = c.get("s3_access_key", None)
        self.s3_secret_key = c.get("s3_secret_key", None)
        self.s3_use_ssl = c.as_bool("s3_use_ssl") if "s3_use_ssl" in c else True
        self.s3_verify_ssl = c.as_bool("s3_verify_ssl") if "s3_verify_ssl" in c else True

        # Node identity
        node_id = c.get("node_id", "auto")
        if node_id == "auto":
            # Generate node ID from Reticulum identity
            identity_hash = RNS.Identity.full_hash(str(owner).encode("utf-8"))
            self.node_id = identity_hash.hex()[:16]  # First 16 hex chars
        else:
            self.node_id = node_id

        # Polling configuration
        self.poll_interval = float(c.get("poll_interval", S3Interface.DEFAULT_POLL_INTERVAL))
        self.batch_size = int(c.get("batch_size", S3Interface.DEFAULT_BATCH_SIZE))

        # Cleanup configuration
        self.retention_period = int(c.get("retention_period", S3Interface.DEFAULT_RETENTION_PERIOD))
        self.cleanup_interval = int(c.get("cleanup_interval", S3Interface.DEFAULT_CLEANUP_INTERVAL))
        self.use_lifecycle_policy = c.as_bool("use_lifecycle_policy") if "use_lifecycle_policy" in c else False

        # Performance settings
        self.max_workers = int(c.get("max_workers", 5))
        self.connection_timeout = int(c.get("connection_timeout", S3Interface.CONNECT_TIMEOUT))
        self.read_timeout = int(c.get("read_timeout", S3Interface.READ_TIMEOUT))

        # Transport settings
        self.IN = c.as_bool("incoming") if "incoming" in c else True
        self.OUT = c.as_bool("outgoing") if "outgoing" in c else True
        self.bitrate = int(c.get("target_bitrate", S3Interface.DEFAULT_BITRATE))
        self.HW_MTU = int(c.get("mtu", S3Interface.DEFAULT_MTU))

        # Interface mode
        if "mode" in c:
            mode_str = c["mode"].lower()
            mode_map = {
                "full": Interface.MODE_FULL,
                "point_to_point": Interface.MODE_POINT_TO_POINT,
                "access_point": Interface.MODE_ACCESS_POINT,
                "roaming": Interface.MODE_ROAMING,
                "boundary": Interface.MODE_BOUNDARY,
                "gateway": Interface.MODE_GATEWAY,
            }
            self.mode = mode_map.get(mode_str, Interface.MODE_GATEWAY)
        else:
            self.mode = Interface.MODE_GATEWAY

        # Reconnection tracking
        self.reconnect_tries = 0
        self.reconnect_backoff = S3Interface.RECONNECT_WAIT

        # State tracking
        self.last_poll_time = 0
        self.last_cleanup_time = 0
        # Use deque for FIFO duplicate detection - thread-safe for append/contains
        self.processed_packets = deque(maxlen=10000)  # Automatically removes oldest
        self.processed_packets_lock = threading.Lock()  # Lock for thread-safety

        # Batching configuration
        self.batch_enabled = c.as_bool("enable_batching") if "enable_batching" in c else True
        self.batch_max_size = int(c.get("batch_max_size", S3Interface.DEFAULT_BATCH_MAX_SIZE))
        self.batch_max_delay = float(c.get("batch_max_delay", S3Interface.DEFAULT_BATCH_MAX_DELAY))
        self.batch_compress = c.as_bool("batch_compress") if "batch_compress" in c else True
        # Smart batching: send critical packets immediately, batch data packets
        self.batch_smart_mode = c.as_bool("batch_smart_mode") if "batch_smart_mode" in c else True

        # Batching state
        self.batch_buffer = []
        self.batch_lock = threading.Lock()
        self.last_batch_send = time.time()  # Initialize with current time

        # Threading
        self.poll_lock = threading.Lock()
        self.s3_client = None
        self.polling_thread = None
        self.cleanup_thread = None
        self.batch_thread = None

        RNS.log(f"Initializing S3Interface {self.name} with bucket {self.s3_bucket}", RNS.LOG_INFO)
        RNS.log(f"Node ID: {self.node_id}", RNS.LOG_DEBUG)
        RNS.log(f"Poll interval: {self.poll_interval}s, Cleanup interval: {self.cleanup_interval}s", RNS.LOG_DEBUG)

        # Start connection
        self.connect()

    def connect(self, initial=True):
        """Establish connection to S3"""
        try:
            if initial:
                RNS.log(f"Establishing S3 connection for {self}...", RNS.LOG_DEBUG)

            # Configure boto3 client
            config = Config(
                signature_version='s3v4',
                connect_timeout=self.connection_timeout,
                read_timeout=self.read_timeout,
                max_pool_connections=self.max_workers,
                retries={'max_attempts': 3}
            )

            # Build client parameters
            client_params = {
                'service_name': 's3',
                'endpoint_url': self.s3_endpoint,
                'region_name': self.s3_region,
                'config': config,
                'use_ssl': self.s3_use_ssl,
                'verify': self.s3_verify_ssl if self.s3_use_ssl else None,
            }

            # Add credentials if provided
            if self.s3_access_key and self.s3_secret_key:
                client_params['aws_access_key_id'] = self.s3_access_key
                client_params['aws_secret_access_key'] = self.s3_secret_key

            # Create S3 client
            self.s3_client = boto3.client(**client_params)

            # Test connection by checking if bucket exists
            try:
                self.s3_client.head_bucket(Bucket=self.s3_bucket)
                RNS.log(f"Successfully connected to S3 bucket: {self.s3_bucket}", RNS.LOG_DEBUG)
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == '404':
                    RNS.log(f"Bucket {self.s3_bucket} does not exist. Please create it first.", RNS.LOG_ERROR)
                    return False
                elif error_code == '403':
                    RNS.log(f"Access denied to bucket {self.s3_bucket}. Check credentials and permissions.", RNS.LOG_ERROR)
                    return False
                else:
                    raise

            self.online = True
            self.never_connected = False
            self.reconnect_tries = 0
            self.reconnect_backoff = S3Interface.RECONNECT_WAIT

            # Start polling thread
            if self.IN and self.polling_thread is None:
                self.polling_thread = threading.Thread(target=self.poll_loop, daemon=True)
                self.polling_thread.start()

            # Start cleanup thread
            if not self.use_lifecycle_policy and self.cleanup_thread is None:
                self.cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
                self.cleanup_thread.start()

            # Start batching thread
            if self.batch_enabled and self.OUT and self.batch_thread is None:
                self.batch_thread = threading.Thread(target=self._batch_flush_loop, daemon=True)
                self.batch_thread.start()

            if initial:
                RNS.log(f"S3Interface {self.name} is ready", RNS.LOG_INFO)
                if self.batch_enabled:
                    mode = "smart" if self.batch_smart_mode else "all packets"
                    RNS.log(f"Batching enabled ({mode}): max_size={self.batch_max_size}, max_delay={self.batch_max_delay}s", RNS.LOG_DEBUG)

            return True

        except NoCredentialsError:
            RNS.log(f"No AWS credentials found for {self}. Please configure credentials.", RNS.LOG_ERROR)
            return False

        except EndpointConnectionError as e:
            RNS.log(f"Cannot connect to S3 endpoint {self.s3_endpoint}: {e}", RNS.LOG_ERROR)
            return False

        except Exception as e:
            if initial:
                RNS.log(f"Initial connection for {self} failed: {e}", RNS.LOG_ERROR)
                RNS.log(f"Retrying connection in {S3Interface.RECONNECT_WAIT} seconds.", RNS.LOG_ERROR)
            else:
                RNS.log(f"Reconnection attempt failed for {self}: {e}", RNS.LOG_DEBUG)
            return False

    def reconnect(self):
        """Reconnection loop with exponential backoff"""
        if self.reconnecting:
            return

        self.reconnecting = True
        self.online = False

        while not self.detached:
            if S3Interface.RECONNECT_MAX_TRIES and self.reconnect_tries >= S3Interface.RECONNECT_MAX_TRIES:
                RNS.log(f"Max reconnection attempts reached for {self}. Giving up.", RNS.LOG_ERROR)
                break

            self.reconnect_tries += 1
            RNS.log(f"Reconnection attempt {self.reconnect_tries} for {self} in {self.reconnect_backoff}s...", RNS.LOG_DEBUG)

            time.sleep(self.reconnect_backoff)

            if self.connect(initial=False):
                RNS.log(f"Reconnected successfully for {self}", RNS.LOG_INFO)
                self.reconnecting = False
                return

            # Exponential backoff with max limit
            self.reconnect_backoff = min(self.reconnect_backoff * 1.5, S3Interface.RECONNECT_BACKOFF_MAX)

        self.reconnecting = False

    def detach(self):
        """Detach interface and stop all threads"""
        RNS.log(f"Detaching {self}...", RNS.LOG_DEBUG)
        self.detached = True
        self.online = False

        # Give threads time to exit gracefully
        time.sleep(1)

        self.s3_client = None
        RNS.log(f"{self} detached", RNS.LOG_DEBUG)

    def poll_loop(self):
        """Main polling loop for receiving packets"""
        RNS.log(f"Starting polling loop for {self}", RNS.LOG_DEBUG)

        while not self.detached:
            try:
                if self.online:
                    current_time = time.time()

                    # Check if it's time to poll
                    if current_time - self.last_poll_time >= self.poll_interval:
                        with self.poll_lock:
                            self.poll_for_packets()
                            self.last_poll_time = current_time

                # Sleep briefly to avoid busy-wait
                time.sleep(0.5)

            except Exception as e:
                RNS.log(f"Error in polling loop for {self}: {e}", RNS.LOG_ERROR)
                self.online = False

                # Attempt reconnection
                if not self.reconnecting:
                    reconnect_thread = threading.Thread(target=self.reconnect, daemon=True)
                    reconnect_thread.start()

                # Wait before retrying
                time.sleep(self.poll_interval)

    def poll_for_packets(self):
        """Poll S3 bucket for new packets"""
        if not self.online or self.s3_client is None:
            return

        try:
            # Calculate timestamp for filtering (get packets from last poll + buffer)
            start_timestamp = int((self.last_poll_time - self.poll_interval * 2) * 1000)

            packets_found = 0
            max_packets = S3Interface.MAX_PACKETS_PER_POLL

            # Poll broadcast packets
            if self.IN and packets_found < max_packets:
                broadcast_packets = self._list_packets(
                    prefix="broadcast/",
                    start_after=f"broadcast/{start_timestamp}",
                    max_items=max_packets - packets_found
                )

                for packet_key in broadcast_packets:
                    if self._process_s3_packet(packet_key):
                        packets_found += 1
                    if packets_found >= max_packets:
                        break

            # Poll direct messages for this node
            if self.IN and packets_found < max_packets:
                direct_packets = self._list_packets(
                    prefix=f"direct/{self.node_id}/",
                    start_after=f"direct/{self.node_id}/{start_timestamp}",
                    max_items=max_packets - packets_found
                )

                for packet_key in direct_packets:
                    if self._process_s3_packet(packet_key):
                        packets_found += 1
                    if packets_found >= max_packets:
                        break

            if packets_found > 0:
                RNS.log(f"{self} received {packets_found} packet(s)", RNS.LOG_DEBUG)

            if packets_found >= max_packets:
                RNS.log(f"{self} hit polling limit ({max_packets} packets), backlog may exist", RNS.LOG_WARNING)

        except Exception as e:
            RNS.log(f"Error polling for packets in {self}: {e}", RNS.LOG_ERROR)
            raise

    def _list_packets(self, prefix, start_after, max_items=None):
        """List packet objects in S3 with pagination"""
        packet_keys = []

        if max_items is None:
            max_items = self.batch_size

        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.s3_bucket,
                Prefix=prefix,
                StartAfter=start_after,
                PaginationConfig={'MaxItems': max_items}
            )

            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']
                        # Only process .pkt files
                        if key.endswith('.pkt'):
                            packet_keys.append(key)

                            # Stop if we've reached the limit
                            if len(packet_keys) >= max_items:
                                return packet_keys

        except ClientError as e:
            RNS.log(f"Error listing objects in {self}: {e}", RNS.LOG_ERROR)
            raise

        return packet_keys

    def _process_s3_packet(self, packet_key):
        """Download and process a packet (single or batched) from S3"""
        try:
            # Extract packet hash from filename for deduplication
            packet_filename = os.path.basename(packet_key)
            packet_hash = packet_filename.split('_')[-1].replace('.pkt', '')

            # Check if already processed (thread-safe)
            with self.processed_packets_lock:
                if packet_hash in self.processed_packets:
                    return False

            # Download packet
            response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=packet_key)
            raw_data = response['Body'].read()

            # Mark as processed (deque automatically removes oldest when maxlen exceeded)
            with self.processed_packets_lock:
                self.processed_packets.append(packet_hash)

            # Check if this is a batched packet
            if raw_data.startswith(S3Interface.BATCH_MAGIC):
                return self._process_batch_packet(raw_data)
            else:
                return self._process_single_packet(raw_data)

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchKey':
                # Packet was already deleted, ignore
                return False
            else:
                RNS.log(f"Error processing packet {packet_key}: {e}", RNS.LOG_ERROR)
                return False
        except Exception as e:
            RNS.log(f"Unexpected error processing packet {packet_key}: {e}", RNS.LOG_ERROR)
            return False

    def cleanup_loop(self):
        """Periodic cleanup of old packets"""
        RNS.log(f"Starting cleanup loop for {self}", RNS.LOG_DEBUG)

        while not self.detached:
            try:
                if self.online:
                    current_time = time.time()

                    # Check if it's time to cleanup
                    if current_time - self.last_cleanup_time >= self.cleanup_interval:
                        self.cleanup_old_packets()
                        self.last_cleanup_time = current_time

                # Sleep for cleanup interval
                time.sleep(min(self.cleanup_interval, 60))

            except Exception as e:
                RNS.log(f"Error in cleanup loop for {self}: {e}", RNS.LOG_ERROR)
                time.sleep(60)

    def cleanup_old_packets(self):
        """Remove packets older than retention period"""
        if not self.online or self.s3_client is None:
            return

        try:
            cutoff_time = int((time.time() - self.retention_period) * 1000)
            deleted_count = 0

            # Cleanup broadcast packets
            deleted_count += self._cleanup_prefix("broadcast/", cutoff_time)

            # Cleanup direct packets (all nodes, not just ours)
            deleted_count += self._cleanup_prefix("direct/", cutoff_time)

            if deleted_count > 0:
                RNS.log(f"{self} cleaned up {deleted_count} old packet(s)", RNS.LOG_DEBUG)

        except Exception as e:
            RNS.log(f"Error during cleanup in {self}: {e}", RNS.LOG_ERROR)

    def _cleanup_prefix(self, prefix, cutoff_timestamp):
        """Cleanup packets under a specific prefix"""
        deleted_count = 0

        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.s3_bucket,
                Prefix=prefix
            )

            delete_keys = []

            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']

                        # Extract timestamp from key
                        filename = os.path.basename(key)
                        if '_' in filename:
                            try:
                                timestamp_str = filename.split('_')[0]
                                timestamp = int(timestamp_str)

                                if timestamp < cutoff_timestamp:
                                    delete_keys.append({'Key': key})

                                    # Batch delete when reaching limit
                                    if len(delete_keys) >= 1000:
                                        self._batch_delete(delete_keys)
                                        deleted_count += len(delete_keys)
                                        delete_keys = []
                            except (ValueError, IndexError):
                                # Skip malformed filenames
                                pass

            # Delete remaining keys
            if delete_keys:
                self._batch_delete(delete_keys)
                deleted_count += len(delete_keys)

        except Exception as e:
            RNS.log(f"Error cleaning up prefix {prefix}: {e}", RNS.LOG_ERROR)

        return deleted_count

    def _process_single_packet(self, packet_data):
        """Process a single, non-batched packet"""
        try:
            # Process incoming packet
            self.rxb += len(packet_data)
            self.owner.inbound(packet_data, self)
            return True
        except Exception as e:
            RNS.log(f"Error processing single packet: {e}", RNS.LOG_ERROR)
            return False

    def _process_batch_packet(self, batch_data):
        """Process a batched packet containing multiple individual packets"""
        try:
            RNS.log(f"{self} received batch packet: {len(batch_data)} bytes", RNS.LOG_DEBUG)

            # Deserialize batch
            packets = self._deserialize_batch(batch_data)

            if not packets:
                RNS.log(f"Empty or invalid batch received", RNS.LOG_WARNING)
                return False

            RNS.log(f"{self} batch contains {len(packets)} packet(s)", RNS.LOG_DEBUG)

            # Process each packet in the batch
            processed_count = 0
            duplicate_count = 0
            for pkt in packets:
                # Check for duplicate packets within batch (thread-safe)
                pkt_hash = hashlib.sha256(pkt).hexdigest()[:8]

                with self.processed_packets_lock:
                    if pkt_hash in self.processed_packets:
                        duplicate_count += 1
                        continue
                    # Mark as processed
                    self.processed_packets.append(pkt_hash)

                # Process packet
                self.rxb += len(pkt)
                self.owner.inbound(pkt, self)
                processed_count += 1

            if duplicate_count > 0:
                RNS.log(f"{self} skipped {duplicate_count} duplicate packet(s) in batch", RNS.LOG_DEBUG)

            if processed_count > 0:
                RNS.log(f"{self} processed batch with {processed_count} new packet(s)", RNS.LOG_DEBUG)

            return processed_count > 0

        except Exception as e:
            RNS.log(f"Error processing batch packet: {e}", RNS.LOG_ERROR)
            return False

    def _batch_delete(self, delete_keys):
        """Batch delete objects from S3"""
        try:
            self.s3_client.delete_objects(
                Bucket=self.s3_bucket,
                Delete={'Objects': delete_keys, 'Quiet': True}
            )
        except Exception as e:
            RNS.log(f"Error during batch delete: {e}", RNS.LOG_ERROR)

    def _serialize_batch(self, packets):
        """
        Serialize multiple packets into a single batch.
        Format: [magic:4] [flags:1] [num_packets:2] [packet1_len:4] [packet1_data] ...
        """
        if not packets:
            return b""

        RNS.log(f"{self} serializing batch: {len(packets)} packet(s)", RNS.LOG_DEBUG)

        # Serialize all packets with their lengths
        packet_data = b""
        for pkt in packets:
            packet_data += struct.pack(">I", len(pkt)) + pkt

        original_size = len(packet_data)
        RNS.log(f"{self} batch raw size: {original_size} bytes", RNS.LOG_DEBUG)

        # Compress if enabled
        flags = 0
        if self.batch_compress:
            try:
                compressed = zlib.compress(packet_data, level=6)
                # Only use compression if it actually reduces size
                if len(compressed) < len(packet_data):
                    compression_ratio = (1 - len(compressed) / original_size) * 100
                    RNS.log(f"{self} batch compressed: {original_size} -> {len(compressed)} bytes ({compression_ratio:.1f}% reduction)", RNS.LOG_DEBUG)
                    packet_data = compressed
                    flags |= S3Interface.BATCH_FLAG_COMPRESSED
                else:
                    RNS.log(f"{self} compression ineffective, sending uncompressed", RNS.LOG_DEBUG)
            except Exception as e:
                RNS.log(f"Compression failed, sending uncompressed: {e}", RNS.LOG_DEBUG)

        # Build header
        header = struct.pack(">4sBH", S3Interface.BATCH_MAGIC, flags, len(packets))
        total_size = len(header) + len(packet_data)
        RNS.log(f"{self} batch total size: {total_size} bytes (header: 7 bytes)", RNS.LOG_DEBUG)

        return header + packet_data

    def _deserialize_batch(self, batch_data):
        """
        Deserialize a batch into individual packets.
        Returns list of packet data.
        """
        try:
            RNS.log(f"{self} deserializing batch: {len(batch_data)} bytes", RNS.LOG_DEBUG)

            # Parse header
            if len(batch_data) < 7:
                raise ValueError("Batch data too short")

            magic, flags, num_packets = struct.unpack_from(">4sBH", batch_data, 0)

            if magic != S3Interface.BATCH_MAGIC:
                raise ValueError(f"Invalid batch magic: {magic}")

            # DoS protection: limit number of packets
            if num_packets > S3Interface.MAX_PACKETS_PER_BATCH:
                RNS.log(f"Batch too large: {num_packets} packets (max {S3Interface.MAX_PACKETS_PER_BATCH})", RNS.LOG_ERROR)
                return []

            RNS.log(f"{self} batch header: {num_packets} packet(s), flags: 0x{flags:02x}", RNS.LOG_DEBUG)

            payload = batch_data[7:]
            compressed_size = len(payload)

            # Decompress if needed
            if flags & S3Interface.BATCH_FLAG_COMPRESSED:
                try:
                    payload = zlib.decompress(payload)
                    decompression_ratio = (len(payload) / compressed_size - 1) * 100
                    RNS.log(f"{self} batch decompressed: {compressed_size} -> {len(payload)} bytes ({decompression_ratio:.1f}% expansion)", RNS.LOG_DEBUG)
                except zlib.error as e:
                    RNS.log(f"Decompression failed: {e}", RNS.LOG_ERROR)
                    return []

            # Extract packets
            packets = []
            offset = 0
            for i in range(num_packets):
                if offset + 4 > len(payload):
                    RNS.log(f"Incomplete packet length at offset {offset}", RNS.LOG_WARNING)
                    break

                pkt_len = struct.unpack_from(">I", payload, offset)[0]
                offset += 4

                # DoS protection: limit packet size
                if pkt_len > S3Interface.MAX_PACKET_SIZE:
                    RNS.log(f"Packet {i} too large: {pkt_len} bytes (max {S3Interface.MAX_PACKET_SIZE})", RNS.LOG_ERROR)
                    break

                if offset + pkt_len > len(payload):
                    RNS.log(f"Incomplete packet data at offset {offset}", RNS.LOG_WARNING)
                    break

                pkt = payload[offset:offset + pkt_len]
                packets.append(pkt)
                RNS.log(f"{self} extracted packet {i+1}/{num_packets}: {pkt_len} bytes", RNS.LOG_DEBUG)
                offset += pkt_len

            RNS.log(f"{self} batch deserialization complete: {len(packets)}/{num_packets} packet(s) extracted", RNS.LOG_DEBUG)
            return packets

        except Exception as e:
            RNS.log(f"Batch deserialization error: {e}", RNS.LOG_ERROR)
            return []

    def _batch_flush_loop(self):
        """Background thread that periodically flushes the batch buffer"""
        RNS.log(f"Starting batch flush loop for {self}", RNS.LOG_DEBUG)

        while not self.detached:
            try:
                time.sleep(0.1)  # Check frequently

                if not self.online:
                    continue  # Skip if offline

                now = time.time()

                with self.batch_lock:
                    if not self.batch_buffer:
                        continue

                    # Calculate current batch size
                    current_size = sum(len(pkt) for pkt in self.batch_buffer)
                    time_since_last_send = now - self.last_batch_send

                    # Flush if batch is full or timeout reached
                    should_flush = (
                        current_size >= self.batch_max_size or
                        time_since_last_send >= self.batch_max_delay
                    )

                    if should_flush:
                        if current_size >= self.batch_max_size:
                            RNS.log(f"{self} flushing batch: size limit reached ({current_size}/{self.batch_max_size} bytes, {len(self.batch_buffer)} packets)", RNS.LOG_DEBUG)
                        else:
                            RNS.log(f"{self} flushing batch: timeout reached ({time_since_last_send:.2f}/{self.batch_max_delay}s, {len(self.batch_buffer)} packets, {current_size} bytes)", RNS.LOG_DEBUG)

                        self._flush_batch()

            except Exception as e:
                RNS.log(f"Error in batch flush loop for {self}: {e}", RNS.LOG_ERROR)
                time.sleep(1)

    def _flush_batch(self):
        """Flush the current batch buffer (must be called with batch_lock held)"""
        if not self.batch_buffer or not self.online:
            return

        try:
            packet_count = len(self.batch_buffer)
            total_raw_size = sum(len(pkt) for pkt in self.batch_buffer)

            RNS.log(f"{self} flushing batch: {packet_count} packet(s), {total_raw_size} bytes raw data", RNS.LOG_DEBUG)

            # Serialize batch
            batch_bytes = self._serialize_batch(self.batch_buffer)

            # Clear buffer
            self.batch_buffer = []
            self.last_batch_send = time.time()

            # Generate filename
            timestamp_ms = int(time.time() * 1000)
            batch_hash = hashlib.sha256(batch_bytes).hexdigest()[:8]
            filename = f"{timestamp_ms}_batch_{self.node_id}_{batch_hash}.pkt"
            key = f"broadcast/{filename}"

            RNS.log(f"{self} uploading batch to S3: {key}", RNS.LOG_DEBUG)

            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=key,
                Body=batch_bytes,
                ContentType='application/octet-stream'
            )

            self.txb += len(batch_bytes)
            RNS.log(f"{self} sent batch: {packet_count} packets, {len(batch_bytes)} bytes ({key})", RNS.LOG_DEBUG)

        except Exception as e:
            RNS.log(f"Batch send failed for {self}: {e}", RNS.LOG_ERROR)
            self.online = False

            # Trigger reconnection
            if not self.reconnecting:
                reconnect_thread = threading.Thread(target=self.reconnect, daemon=True)
                reconnect_thread.start()

    def _send_single_packet(self, data):
        """Send a single packet (non-batched mode)"""
        try:
            # Generate packet filename
            timestamp_ms = int(time.time() * 1000)
            packet_hash = hashlib.sha256(data).hexdigest()[:8]
            packet_filename = f"{timestamp_ms}_{self.node_id}_{packet_hash}.pkt"

            # Upload to broadcast prefix
            packet_key = f"broadcast/{packet_filename}"

            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=packet_key,
                Body=data,
                ContentType='application/octet-stream'
            )

            self.txb += len(data)
            RNS.log(f"{self} sent packet: {packet_key}", RNS.LOG_EXTREME)

        except Exception as e:
            RNS.log(f"Error sending packet via {self}: {e}", RNS.LOG_ERROR)
            self.online = False

            # Trigger reconnection
            if not self.reconnecting:
                reconnect_thread = threading.Thread(target=self.reconnect, daemon=True)
                reconnect_thread.start()

    def _is_critical_packet(self, data):
        """Determine if packet is critical and should be sent immediately"""
        if len(data) < 1:
            return False

        # Extract packet type from flags byte
        packet_type = data[0] & 0x03

        # Critical packets: announces, link requests, proofs
        is_critical = packet_type in (
            S3Interface.PACKET_TYPE_ANNOUNCE,
            S3Interface.PACKET_TYPE_LINKREQUEST,
            S3Interface.PACKET_TYPE_PROOF
        )

        return is_critical

    def process_outgoing(self, data):
        """Send data via S3"""
        if not self.OUT or not self.online:
            return

        if self.batch_enabled:
            # Smart batching: send critical packets immediately
            if self.batch_smart_mode and self._is_critical_packet(data):
                packet_type = data[0] & 0x03
                packet_type_name = {
                    S3Interface.PACKET_TYPE_ANNOUNCE: "ANNOUNCE",
                    S3Interface.PACKET_TYPE_LINKREQUEST: "LINKREQUEST",
                    S3Interface.PACKET_TYPE_PROOF: "PROOF"
                }.get(packet_type, "UNKNOWN")
                RNS.log(f"{self} sending critical packet immediately: {packet_type_name}, {len(data)} bytes", RNS.LOG_DEBUG)
                self._send_single_packet(data)
            else:
                # Add to batch buffer
                with self.batch_lock:
                    was_empty = len(self.batch_buffer) == 0
                    self.batch_buffer.append(data)
                    current_batch_size = sum(len(pkt) for pkt in self.batch_buffer)

                    # Reset timer when adding first packet to empty buffer
                    if was_empty:
                        self.last_batch_send = time.time()
                        RNS.log(f"{self} started new batch with packet: {len(data)} bytes", RNS.LOG_DEBUG)
                    else:
                        RNS.log(f"{self} buffered packet: {len(data)} bytes ({len(self.batch_buffer)} packets, {current_batch_size} bytes total in batch)", RNS.LOG_EXTREME)
        else:
            # Send immediately without batching
            self._send_single_packet(data)

    def __str__(self):
        return f"S3Interface[{self.name}]"


# Required for external interface loading
interface_class = S3Interface
