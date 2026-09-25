# AI-Assisted Intelligent Data Recovery and Digital Evidence Reconstruction

This project is a cybersecurity and AI-based digital evidence recovery platform designed to assist in identifying, reconstructing, classifying, and prioritizing recoverable information from damaged, deleted, fragmented, or partially corrupted storage data. The system goes beyond traditional file recovery by analyzing recovered fragments, identifying relationships between them, evaluating reconstruction possibilities, performing integrity analysis, and presenting meaningful recovery insights through an intuitive forensic dashboard.

The frontend has been developed using React and Vite with a modern dark-themed forensic dashboard interface. The application includes Dashboard, Scan Data, Fragments, Evidence, and Analytics sections, along with persistent sidebar and top navigation. React Router is used for client-side navigation, while reusable components and responsive styling provide a structured interface for integrating the backend forensic processing and AI/ML pipeline.

The project follows a modular architecture connecting the frontend with a FastAPI backend and machine learning pipeline. The system includes file scanning, fragment generation, file-type classification, fragment relationship analysis, reconstruction, integrity analysis, evidence prioritization, and visual image recovery with reference matching and damage analysis. The architecture is designed to support further integration of advanced forensic processing, machine learning models, database services, and real-time recovery results.

## Project Structure

```text
refrag-ai/

│
├── backend/
│
├── src/
│   ├── components/
│   │   ├── Sidebar.jsx
│   │   ├── Topbar.jsx
│   │   └── ...
│   │
│   ├── pages/
│   │   ├── Dashboard.jsx
│   │   ├── ScanData.jsx
│   │   ├── Fragments.jsx
│   │   ├── Evidence.jsx
│   │   └── Analytics.jsx
│   │
│   ├── services/
│   │   └── api.js
│   │
│   ├── App.jsx
│   └── main.jsx
│
├── .gitignore
├── package.json
├── requirements.txt
├── vite.config.js
└── README.md
```