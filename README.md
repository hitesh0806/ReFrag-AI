# AI-Assisted Intelligent Data Recovery and Digital Evidence Reconstruction

ReFrag-AI is a cybersecurity and AI-based digital evidence recovery platform designed to assist in identifying, reconstructing, classifying, and prioritizing recoverable information from damaged, deleted, fragmented, or partially corrupted storage data.

The system goes beyond traditional file recovery by analyzing recovered fragments, identifying relationships between them, evaluating reconstruction possibilities, performing integrity analysis, and presenting meaningful recovery insights through an intuitive forensic dashboard.

The frontend is developed using React and Vite with a modern dark-themed forensic dashboard interface. The application includes Dashboard, Scan Data, Fragments, Evidence, and Analytics sections.

The project follows a modular architecture connecting the React frontend with a FastAPI backend and forensic processing services.

## Live Deployment
| Component | Platform | Link |
|-----------|----------|------|
| Frontend | Vercel | [Live Application](https://refrag-ai.vercel.app/) |
| Backend API | Render | [API Server](https://refrag-ai-backend.onrender.com) |
| API Documentation | Swagger UI | [API Docs](https://refrag-ai-backend.onrender.com/docs) |

## Core Features
- Forensic data and fragment ingestion
- Fragment analysis and classification
- Fragment relationship detection
- Reconstruction of fragmented files
- Reconstruction validation and integrity analysis
- Evidence prioritization
- Image recovery and damage analysis
- Case-based forensic data management
- REST API integration

## Technology Stack

### Frontend
- React
- Vite
- JavaScript
- React Router
- CSS

### Backend
- Python
- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic

### Database
- PostgreSQL

## Project Structure
```text
ReFrag-AI/
│
├── backend/
│   ├── app/
│   │   ├── models/
│   │   ├── routers/
│   │   ├── schemas/
│   │   └── services/
│   └── requirements.txt
│
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/
│   ├── App.jsx
│   └── main.jsx
│
├── scripts/
├── scratch/
├── test_dataset/
├── package.json
├── vite.config.js
└── README.md
```

## Local Setup
Clone the repository:

```bash
git clone https://github.com/hitesh0806/ReFrag-AI.git
cd ReFrag-AI
```

### Frontend
```bash
npm install
npm run dev
```

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend API will be available at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

## Contributors
- [Hitesh T G](https://github.com/hitesh0806)
- [Paresh R](https://github.com/Paresh-Gowda)

## Repository
[github.com/hitesh0806/ReFrag-AI](https://github.com/hitesh0806/ReFrag-AI)