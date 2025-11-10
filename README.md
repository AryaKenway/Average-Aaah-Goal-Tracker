# Goal Tracker — Sprint 1

## Quick start (local, dev)
1. Clone repo
   - `git clone git@github.com:<user>/goal-tracker.git && cd goal-tracker`

2. Start services with Docker (recommended)
   - Copy backend env: `cp backend/.env.example backend/.env`
   - `docker compose up --build`
   - Backend: http://localhost:5000/api/goals
   - Frontend dev (if used): http://localhost:5173

3. Run backend locally (without Docker)
   - `cd backend`
   - `cp .env.example .env`
   - `npm install`
   - `node server.js`

4. Run frontend locally (if implemented)
   - `cd frontend`
   - `npm install`
   - `npm run dev`

## Branching / workflow
- Feature branches: `feature/{name}/{task}` e.g. `feature/akkshith/backend-api`
- Base branch: `develop` (all work merges into develop, tested then merged to main)
- PRs: require 1 reviewer and successful local run

## Contacts
- PO / Docker: Nischay Chhetri
- Scrum Master: Arya Acharya
# Goal Tracker

A minimal goal-tracking web app for practicing Git collaboration.

### Tech Stack
- Frontend: React, Tailwind CSS, Axios
- Backend: Node.js, Express, MongoDB
- Deployment: Docker

### Team
| Name | ID | Role |
|------|----|------|
| Arya Acharya | 2260346 | Scrum Master and Data Analyzer |
| Sumeet Bafna | 2260450 | Frontend Developer and Software Tester |
| Akkshith Reddy | 2260443 | Backend Developer and Database Integrator |
| Nischay Chhetri | 2260405 | Product Owner and Docker Master  |
| Aayush Paudel | 2260308 | Frontend Developer|

### Branching Strategy
- `main` – stable branch (protected)
- `develop` – active sprint branch
- `feature/<name>/<task>` – individual branches

### Folder Structure
