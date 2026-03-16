# RetroGameAPI

A RESTful API built in Go for managing a retro game marketplace. Users can create accounts, browse and add games and consoles, and trade games with other users.

Built as a class project to practice backend development, REST API design, and Go fundamentals.

## Features

- User account creation and authentication
- Full CRUD for games and consoles
- Trade system — users can propose and manage trades with other users
- RESTful routing following standard HTTP conventions

## Tech stack

- **Language:** Go
- **Architecture:** REST API
- **Data:** JSON request/response

## Getting started

### Prerequisites

- Go 1.20 or higher installed

### Run locally

```bash
git clone https://github.com/xd-dbug/RetroGameAPI.git
cd RetroGameAPI
go run main.go
```

The server will start on `http://localhost:8080` by default.

## API overview

| Method | Endpoint | Description |
|---|---|---|
| POST | `/users` | Create a new user account |
| GET | `/games` | List all games |
| POST | `/games` | Add a new game |
| GET | `/games/:id` | Get a game by ID |
| PUT | `/games/:id` | Update a game |
| DELETE | `/games/:id` | Delete a game |
| GET | `/consoles` | List all consoles |
| POST | `/consoles` | Add a new console |
| GET | `/consoles/:id` | Get a console by ID |
| PUT | `/consoles/:id` | Update a console |
| DELETE | `/consoles/:id` | Delete a console |
| POST | `/trades` | Propose a trade |
| GET | `/trades/:id` | Get trade details |

> Note: Endpoint paths may vary slightly — check the source for exact routes.

## What I learned

- Structuring a REST API in Go from scratch
- HTTP routing and handler patterns
- Designing resource-based endpoints
- Working with JSON serialization in Go
