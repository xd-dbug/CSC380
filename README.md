# RetroGameAPI

[![Go](https://img.shields.io/badge/Go-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![Gin](https://img.shields.io/badge/Gin-008ECF?style=flat&logo=gin&logoColor=white)](https://gin-gonic.com/)
[![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=flat&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Kafka](https://img.shields.io/badge/Kafka-231F20?style=flat&logo=apachekafka&logoColor=white)](https://kafka.apache.org/)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=flat&logo=prometheus&logoColor=white)](https://prometheus.io/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)

## Project Overview
RetroGameAPI is a robust, production-ready RESTful API developed for managing retro video game collections and facilitating peer-to-peer trades. Designed with scalability and observability in mind, the project implements a microservices-inspired architecture, featuring asynchronous event processing and comprehensive system monitoring.

## Features
- **User Authentication**: Secure user registration and session management using JWT (JSON Web Tokens).
- **Collection Management**: Full CRUD operations for personal game collections and console lists.
- **Trade System**: Peer-to-peer trade workflow allowing users to create, accept, or reject trade offers with automatic ownership transfer.
- **Asynchronous Notifications**: Event-driven email notifications powered by Apache Kafka and a dedicated consumer service.
- **Observability**: Real-time metrics collection via Prometheus, covering trade volumes, user growth, and system performance.
- **High Availability**: Containerized deployment with Nginx load balancing and Kubernetes Horizontal Pod Autoscaling (HPA) support.

## Tech Stack
- **Backend**: Go (1.25) with the Gin Web Framework.
- **Database**: MySQL for persistent relational data storage.
- **Message Broker**: Apache Kafka for reliable asynchronous event delivery.
- **Monitoring**: Prometheus for metrics collection and Grafana for visualization.
- **Infrastructure**: Docker & Docker Compose for orchestration; Kubernetes manifests for cloud-native deployment.
- **Load Balancing**: Nginx configured as a reverse proxy and load balancer.

## Project Structure
```text
RetroGameAPI/
├── email-consumer/    # Dedicated service for processing Kafka notification events
├── k8/                # Kubernetes manifests (Deployments, Services, ConfigMaps, HPA)
├── prometheus/        # Monitoring configuration and Dockerfile
├── retro-ui/          # React-based frontend application
├── handlers_*.go      # API controller logic organized by domain entity
├── main.go            # Application entry point, router, and middleware configuration
├── models.go          # Data structures and database schema definitions
├── db_helpers.go      # Shared database utility functions
├── kafka.go           # Kafka producer implementation
├── docker-compose.yml # Local multi-container development environment
└── init.sql           # Database schema initialization script
```

## API Endpoints

### Authentication
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| POST | `/register` | Create a new user account | No |
| POST | `/login` | Authenticate and receive JWT | No |

### Games
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| GET | `/games` | List all games | No |
| GET | `/users/:userId/games` | List games owned by a specific user | No |
| POST | `/games` | Add one or multiple games to collection | Yes |
| PUT | `/games/:id` | Replace an existing game entry | Yes |
| PATCH | `/games/:id` | Partially update game details | Yes |
| DELETE | `/games/:id` | Remove a game from collection | Yes |

### Trade Offers
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| POST | `/trade-offers` | Create a new trade proposal | Yes |
| GET | `/trade-offers/incoming` | View received trade offers | Yes |
| GET | `/trade-offers/outgoing` | View sent trade offers | Yes |
| PATCH | `/trade-offers/:id/status` | Accept or reject a trade offer | Yes |

### Consoles & Companies
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| GET | `/consoles` | List all gaming consoles | No |
| GET | `/consoles/:id` | Get details for a specific console | No |
| POST | `/consoles` | Add a new console to the directory | Yes |
| GET | `/companies` | List game publishers and manufacturers | No |

### Monitoring
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| GET | `/metrics` | Prometheus metrics export |

## Environment Variables
The application expects the following environment variables for configuration:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DB_USER` | MySQL username | `root` |
| `DB_PASSWORD` | MySQL password | `password` |
| `DB_HOST` | MySQL database host | `localhost` |
| `DB_PORT` | MySQL database port | `3306` |
| `DB_NAME` | MySQL database name | `RetroGameDB` |
| `JWT_SECRET` | Secret key for JWT signing | `secret` |
| `KAFKA_BROKER` | Kafka broker address | `broker:19092` |
| `SMTP_HOST` | SMTP server for notifications | `sandbox.smtp.mailtrap.io` |
| `SMTP_PORT` | SMTP server port | `25` |
| `SMTP_USER` | SMTP authentication user | - |
| `SMTP_PASSWORD` | SMTP authentication password | - |

## How to Run Locally

### Prerequisites
- Docker and Docker Compose installed.

### Steps
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd RetroGameAPI
   ```

2. **Launch the stack**:
   Use Docker Compose to build and start all services (API instances, DB, Kafka, Prometheus, etc.):
   ```bash
   docker-compose up -d --build
   ```

3. **Verify the services**:
   - **API**: `http://localhost:80` (via Nginx Load Balancer)
   - **Prometheus**: `http://localhost:9090`
   - **Grafana**: `http://localhost:3000` (Default login: `admin`/`admin`)
   - **MySQL**: `localhost:3307`

4. **Shutdown**:
   ```bash
   docker-compose down
   ```

