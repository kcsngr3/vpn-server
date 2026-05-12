**Architecture Overview**

The system consists of multiple VPN server instances deployed across different geographic regions, each running as a standalone Go binary on a Linux host. Every region operates independently — if one goes down, the others continue serving clients unaffected.

**Database Layer**

Each regional VM runs a local PostgreSQL instance inside a Docker container. This database acts as a publisher in PostgreSQL's logical replication model. Every VPN event — session connect, disconnect, heartbeat — is written locally first, keeping the write path fast and independent of network conditions between regions.

A dedicated central VM runs a single PostgreSQL subscriber container. This subscriber maintains active replication slots connected to every regional publisher. As each region writes session data locally, PostgreSQL streams those changes to the central database automatically. The central database becomes the single aggregated view of all regions combined — without any application-level data synchronization code.

This fan-in replication pattern is the core database technology demonstration. It shows logical replication across multiple independent publishers, replication slot management, and a real-world pattern used in distributed analytics systems.

**Transactional Control**

When a VPN session disconnects, the final state — bytes transferred, packets dropped, drop rate, disconnect timestamp — must be written atomically together with the final heartbeat failure record. This uses an explicit PostgreSQL transaction wrapping two statements. If either fails, both roll back, leaving no inconsistent session state in the database.

**Container Architecture**

Each regional VM runs one Docker container: the PostgreSQL publisher. The VPN server runs directly on the host as a systemd service, because it requires kernel-level access to create TUN interfaces and manipulate routing tables — capabilities that conflict with Docker's isolation model.

The central VM runs two containers managed by Docker Compose: the PostgreSQL subscriber and the monitoring web service. Keeping these as separate containers follows the single responsibility principle — the database and the web service can be restarted, updated, or scaled independently.

**Monitoring Service**

The monitoring web service reads exclusively from the central database. It exposes a REST API consumed by a React frontend that displays all regions side by side in real time. Because the central database already contains all regional data via replication, the monitoring service needs no knowledge of individual region addresses or credentials — it has one database connection and one source of truth.

Adding a new region in the future requires only deploying a new VM with the same Go binary and Docker configuration, then adding one replication subscription on the central database. No existing code changes.