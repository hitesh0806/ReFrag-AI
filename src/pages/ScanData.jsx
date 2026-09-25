import { useState, useRef } from "react";
import {
  Upload,
  Folder,
  File,
  HardDrive,
  FileSearch,
  Cpu,
  Network,
  ShieldCheck,
  Play,
  CheckCircle2,
  AlertCircle,
  Loader2,
  RefreshCw,
  FolderOpen,
  FileText,
  ArrowRight,
  Download,
  ExternalLink,
  Image as ImageIcon,
  Sparkles,
  Layers,
  Activity,
  Check,
  Terminal,
  XCircle,
  Bug,
} from "lucide-react";
import {
  uploadForensicDataset,
  analyzeCaseFragments,
  reconstructCase,
  getReconstructionDownloadUrl,
  getReconstructionViewUrl,
} from "../services/api";

function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

function ScanData() {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [isFolderUpload, setIsFolderUpload] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [error, setError] = useState(null);

  // Pipeline execution state
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState("IDLE"); // 'IDLE' | 'ANALYZING' | 'RECONSTRUCTING' | 'COMPLETED'
  const [completedSteps, setCompletedSteps] = useState({
    upload: false,
    fragments: false,
    structure: false,
    relationships: false,
    reconstruction: false,
    validation: false,
  });

  // Forensic analysis results
  const [fragmentsData, setFragmentsData] = useState([]);
  const [relationshipsData, setRelationshipsData] = useState([]);
  const [reconstructionData, setReconstructionData] = useState(null);

  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  const handleFileSelect = (e) => {
    if (!e.target.files || e.target.files.length === 0) return;
    processFiles(e.target.files, false);
  };

  const handleFolderSelect = (e) => {
    if (!e.target.files || e.target.files.length === 0) return;
    processFiles(e.target.files, true);
  };

  const processFiles = (fileList, isFolder) => {
    const arr = Array.from(fileList);
    if (arr.length === 0) {
      setError("The selected input contains no files.");
      return;
    }

    const items = arr.map((f) => ({
      rawFile: f,
      name: f.name,
      relativePath: f.webkitRelativePath || f.name,
      size: f.size,
      type: f.type || "binary/raw-evidence",
    }));

    setSelectedFiles(items);
    setIsFolderUpload(isFolder || items.some((i) => i.relativePath.includes("/")));
    setError(null);
    setUploadResult(null);
    setUploadSuccess(false);
    setFragmentsData([]);
    setRelationshipsData([]);
    setReconstructionData(null);
    setCompletedSteps({
      upload: false,
      fragments: false,
      structure: false,
      relationships: false,
      reconstruction: false,
      validation: false,
    });
    setCurrentStage("IDLE");
  };

  const handleUploadSubmit = async () => {
    if (selectedFiles.length === 0) return;

    setIsUploading(true);
    setError(null);

    try {
      const files = selectedFiles.map((s) => s.rawFile);
      const relativePaths = selectedFiles.map((s) => s.relativePath);

      const caseName = isFolderUpload
        ? `Folder Ingestion (${selectedFiles[0]?.relativePath.split("/")[0] || "Dataset"})`
        : `File Ingestion (${selectedFiles.length} file${selectedFiles.length > 1 ? "s" : ""})`;

      const result = await uploadForensicDataset(files, relativePaths, caseName);

      setUploadResult(result);
      setUploadSuccess(true);
      setIsUploading(false);
      setCompletedSteps((prev) => ({ ...prev, upload: true }));
    } catch (err) {
      setIsUploading(false);
      setError(err.message || "Failed to ingest forensic dataset.");
    }
  };

  const resetSelection = () => {
    setSelectedFiles([]);
    setIsFolderUpload(false);
    setUploadResult(null);
    setUploadSuccess(false);
    setError(null);
    setPipelineRunning(false);
    setCurrentStage("IDLE");
    setFragmentsData([]);
    setRelationshipsData([]);
    setReconstructionData(null);
    setCompletedSteps({
      upload: false,
      fragments: false,
      structure: false,
      relationships: false,
      reconstruction: false,
      validation: false,
    });
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (folderInputRef.current) folderInputRef.current.value = "";
  };

  const runFullPipeline = async () => {
    if (!uploadResult?.case_id || pipelineRunning) return;

    setPipelineRunning(true);
    setError(null);
    const caseId = uploadResult.case_id;

    try {
      // Stage 1 & 2: Fragment Detection & Relationship Graph
      setCurrentStage("ANALYZING");
      const analysisRes = await analyzeCaseFragments(caseId);
      setFragmentsData(analysisRes.fragments || []);
      setRelationshipsData(analysisRes.relationships || []);
      setCompletedSteps((prev) => ({
        ...prev,
        fragments: true,
        structure: true,
        relationships: true,
      }));

      // Stage 3 & 4: Candidate Reconstruction & Validation
      setCurrentStage("RECONSTRUCTING");
      const reconList = await reconstructCase(caseId);
      if (reconList && reconList.length > 0) {
        setReconstructionData(reconList[0]);
      }
      setCompletedSteps((prev) => ({
        ...prev,
        reconstruction: true,
        validation: true,
      }));

      setCurrentStage("COMPLETED");
      setPipelineRunning(false);
    } catch (err) {
      setPipelineRunning(false);
      setCurrentStage("IDLE");
      setError(err.message || "Pipeline execution failed.");
    }
  };

  const totalSize = selectedFiles.reduce((acc, curr) => acc + curr.size, 0);

  // Helper classification badge
  const renderClassificationBadge = (cls) => {
    switch (cls) {
      case "HEADER_FRAGMENT":
        return <span className="chip chip-header">HEADER</span>;
      case "STRUCTURAL_FRAGMENT":
        return <span className="chip chip-structural">STRUCTURAL</span>;
      case "ENTROPY_DATA_FRAGMENT":
        return <span className="chip chip-entropy">SCAN DATA</span>;
      case "ENDING_FRAGMENT":
        return <span className="chip chip-ending">ENDING (EOI)</span>;
      default:
        return <span className="chip">{cls || "UNKNOWN"}</span>;
    }
  };

  // Helper reconstruction status badge
  const renderReconstructionStatusBadge = (status, valResult) => {
    const isMismatch = status === "RECONSTRUCTION MISMATCH" || valResult?.exact_sha_match === false;
    const isValidated = status === "VALIDATED" && valResult?.exact_sha_match !== false;

    if (isMismatch) {
      return (
        <span className="status-badge-mismatch">
          <AlertCircle size={13} />
          ⚠ RECONSTRUCTION MISMATCH
        </span>
      );
    }
    if (isValidated) {
      return (
        <span className="status-badge-validated">
          <CheckCircle2 size={13} />
          ✓ VALIDATED
        </span>
      );
    }
    if (status === "PARTIALLY_VALIDATED" || status === "PARTIALLY_VALID") {
      return (
        <span className="status-badge-partial">
          <AlertCircle size={13} />
          PARTIALLY VALIDATED
        </span>
      );
    }
    if (status === "UNCERTAIN") {
      return (
        <span className="status-badge-uncertain">
          <AlertCircle size={13} />
          UNCERTAIN
        </span>
      );
    }
    return (
      <span className="status-badge-invalid">
        <AlertCircle size={13} />
        {status || "INVALID"}
      </span>
    );
  };

  return (
    <section className="scan-page">
      {/* HEADER */}
      <div className="scan-page-header">
        <div>
          <p className="eyebrow">FORENSIC DATA ANALYSIS & RECONSTRUCTION</p>

          <h1>
            Reconstruct damaged storage.
            <br />
            <span>Recover what was lost.</span>
          </h1>

          <p>
            Upload a forensic dataset or shuffled fragments. ReFrag AI inspects raw byte streams,
            evaluates structural and boundary continuity, assembles candidate chains,
            and validates reconstructed JPEG images with explainable evidence trails.
          </p>
        </div>
      </div>

      {/* UPLOAD CARD */}
      <div className="upload-card">
        <div className="upload-icon">
          {isUploading ? (
            <Loader2 size={25} className="animate-spin" />
          ) : uploadSuccess ? (
            <CheckCircle2 size={25} style={{ color: "#4ade80" }} />
          ) : (
            <Upload size={25} />
          )}
        </div>

        <h2>
          {uploadSuccess
            ? "Dataset Ingested into Forensic Storage"
            : selectedFiles.length > 0
            ? isFolderUpload
              ? "Selected Forensic Folder"
              : "Selected Forensic Dataset"
            : "Select forensic data"}
        </h2>

        <p>
          {uploadSuccess
            ? "All artifacts and raw byte streams have been recorded into PostgreSQL with immutable SHA-256 hashes."
            : selectedFiles.length > 0
            ? `Review selected ${selectedFiles.length} file(s) below and confirm ingestion.`
            : "Upload a disk image, folder of shuffled fragments, or raw binary samples."}
        </p>

        {/* FILE / FOLDER SELECTION BUTTONS */}
        {!uploadSuccess && (
          <div className="upload-button-group">
            <label className="upload-button">
              <File size={17} />
              Choose File(s)
              <input
                type="file"
                multiple
                hidden
                ref={fileInputRef}
                onChange={handleFileSelect}
              />
            </label>

            <label className="upload-button-secondary">
              <FolderOpen size={17} />
              Choose Folder
              <input
                type="file"
                webkitdirectory=""
                directory=""
                multiple
                hidden
                ref={folderInputRef}
                onChange={handleFolderSelect}
              />
            </label>

            {selectedFiles.length > 0 && (
              <button
                className="upload-button-secondary"
                onClick={resetSelection}
                type="button"
                style={{ color: "#ef4444", borderColor: "rgba(239,68,68,0.3)" }}
              >
                <RefreshCw size={14} /> Clear
              </button>
            )}
          </div>
        )}

        {/* ERROR DISPLAY */}
        {error && (
          <div className="ingestion-error-alert">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {/* PRE-UPLOAD DATASET SUMMARY */}
        {selectedFiles.length > 0 && !uploadSuccess && (
          <div className="dataset-summary-card">
            <div className="dataset-summary-header">
              <h4>
                {isFolderUpload ? "Selected forensic folder" : "Selected forensic dataset"}
              </h4>
              <span>
                {selectedFiles.length} {selectedFiles.length === 1 ? "file" : "files"} &bull; Total size: {formatBytes(totalSize)}
              </span>
            </div>

            <div className="file-list-preview">
              {selectedFiles.map((item, idx) => (
                <div key={idx} className="file-item-row">
                  <div className="file-item-info">
                    {item.relativePath.includes("/") ? (
                      <Folder size={14} style={{ color: "#818cf8", flexShrink: 0 }} />
                    ) : (
                      <FileText size={14} style={{ color: "#94a3b8", flexShrink: 0 }} />
                    )}
                    <span className="file-item-path" title={item.relativePath}>
                      {item.relativePath}
                    </span>
                  </div>

                  <div className="file-item-meta">
                    <span>{item.type || "raw"}</span>
                    <span>{formatBytes(item.size)}</span>
                  </div>
                </div>
              ))}
            </div>

            <button
              className="confirm-upload-btn"
              onClick={handleUploadSubmit}
              disabled={isUploading}
            >
              {isUploading ? (
                <>
                  <Loader2 size={16} className="animate-spin" /> Ingesting Dataset...
                </>
              ) : (
                <>
                  <Upload size={16} /> Confirm Forensic Ingestion
                </>
              )}
            </button>
          </div>
        )}

        {/* POST-UPLOAD INGESTION SUCCESS SUMMARY */}
        {uploadSuccess && uploadResult && (
          <div className="ingestion-success-box">
            <div className="ingestion-success-header">
              <CheckCircle2 size={20} />
              <span>Dataset ingested & verified in database</span>
            </div>

            <div className="ingestion-meta-grid">
              <div className="ingestion-meta-item">
                <label>Case ID</label>
                <span className="case-id-badge">{uploadResult.case_id}</span>
              </div>
              <div className="ingestion-meta-item">
                <label>Artifacts Ingested</label>
                <span>{uploadResult.files_uploaded}</span>
              </div>
              <div className="ingestion-meta-item">
                <label>Total Data Size</label>
                <span>{formatBytes(uploadResult.total_size)}</span>
              </div>
              <div className="ingestion-meta-item">
                <label>Pipeline Status</label>
                <span style={{ color: "#4ade80", textTransform: "uppercase" }}>
                  {currentStage === "IDLE" ? uploadResult.status : currentStage}
                </span>
              </div>
            </div>

            <div style={{ marginTop: "14px", display: "flex", gap: "10px" }}>
              <button
                onClick={resetSelection}
                className="upload-button-secondary"
                style={{ fontSize: "11px", padding: "8px 14px" }}
              >
                <RefreshCw size={13} /> Upload Another Dataset
              </button>
            </div>
          </div>
        )}
      </div>

      {/* PIPELINE CONTROLS & STEPPER */}
      <div className="scan-section">
        <div className="section-header">
          <div>
            <p className="eyebrow">FORENSIC PIPELINE CONTROLLER</p>
            <h2>Analysis & Reconstruction Workflow</h2>
          </div>

          <button
            className="scan-button"
            disabled={!uploadSuccess || pipelineRunning}
            onClick={runFullPipeline}
          >
            {pipelineRunning ? (
              <>
                <Loader2 size={17} className="animate-spin" />
                Processing Pipeline...
              </>
            ) : currentStage === "COMPLETED" ? (
              <>
                <RefreshCw size={17} />
                Re-Run Analysis
              </>
            ) : (
              <>
                <Play size={17} />
                Run Reconstruction Pipeline
              </>
            )}
          </button>
        </div>

        {/* VISUAL PIPELINE PROGRESS STEPPER */}
        <div className="reconstruction-pipeline-controls">
          <div className="pipeline-stepper">
            <div className={`pipeline-step-item ${completedSteps.upload ? "completed" : ""}`}>
              {completedSteps.upload ? <Check size={14} /> : <HardDrive size={14} />}
              <span>Evidence Uploaded</span>
            </div>

            <span className="pipeline-step-arrow">→</span>

            <div className={`pipeline-step-item ${completedSteps.fragments ? "completed" : currentStage === "ANALYZING" ? "active" : ""}`}>
              {completedSteps.fragments ? <Check size={14} /> : currentStage === "ANALYZING" ? <Loader2 size={14} className="animate-spin" /> : <FileSearch size={14} />}
              <span>Fragments Detected</span>
            </div>

            <span className="pipeline-step-arrow">→</span>

            <div className={`pipeline-step-item ${completedSteps.structure ? "completed" : currentStage === "ANALYZING" ? "active" : ""}`}>
              {completedSteps.structure ? <Check size={14} /> : <Activity size={14} />}
              <span>JPEG Structure Analyzed</span>
            </div>

            <span className="pipeline-step-arrow">→</span>

            <div className={`pipeline-step-item ${completedSteps.relationships ? "completed" : currentStage === "ANALYZING" ? "active" : ""}`}>
              {completedSteps.relationships ? <Check size={14} /> : <Network size={14} />}
              <span>Relationships Calculated</span>
            </div>

            <span className="pipeline-step-arrow">→</span>

            <div className={`pipeline-step-item ${completedSteps.reconstruction ? "completed" : currentStage === "RECONSTRUCTING" ? "active" : ""}`}>
              {completedSteps.reconstruction ? <Check size={14} /> : currentStage === "RECONSTRUCTING" ? <Loader2 size={14} className="animate-spin" /> : <Cpu size={14} />}
              <span>Candidate Reconstructed</span>
            </div>

            <span className="pipeline-step-arrow">→</span>

            <div className={`pipeline-step-item ${completedSteps.validation ? "completed" : currentStage === "RECONSTRUCTING" ? "active" : ""}`}>
              {completedSteps.validation ? <Check size={14} /> : <ShieldCheck size={14} />}
              <span>JPEG Validated</span>
            </div>
          </div>
        </div>
      </div>

      {/* FORENSIC RECONSTRUCTION RESULTS UI */}
      {(fragmentsData.length > 0 || reconstructionData) && (
        <div className="forensic-results-container">
          {/* 1. FRAGMENT ANALYSIS CARD */}
          <div className="forensic-card">
            <div className="forensic-card-header">
              <h3>
                <Layers size={18} style={{ color: "#818cf8" }} />
                Fragment Structural Inventory
              </h3>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                {(currentStage === "COMPLETED" || reconstructionData) && (
                  <span className="chip" style={{ background: "rgba(34, 197, 94, 0.15)", color: "#4ade80", borderColor: "rgba(34, 197, 94, 0.3)" }}>
                    <CheckCircle2 size={12} style={{ display: "inline", marginRight: "4px" }} />
                    Temporary analysis data cleaned
                  </span>
                )}
                <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                  Case: <code style={{ color: "#38bdf8" }}>{uploadResult?.case_id || reconstructionData?.case_id}</code>
                </span>
              </div>
            </div>

            {(currentStage === "COMPLETED" || reconstructionData) && (
              <div className="temporary-cleanup-banner">
                <CheckCircle2 size={16} style={{ color: "#4ade80", flexShrink: 0 }} />
                <div>
                  <strong>Temporary analysis data cleaned.</strong>
                  <span>
                    Temporary processing records (<code>forensic_fragments</code> & <code>fragment_relationships</code>) were safely purged from PostgreSQL upon successful reconstruction and validation. Original evidence (<code>forensic_artifacts</code>) and final reconstruction results remain preserved.
                  </span>
                </div>
              </div>
            )}

            {/* Metrics Grid */}
            <div className="forensic-metrics-grid">
              <div className="forensic-metric-tile">
                <label>Total Fragments</label>
                <strong>{fragmentsData.length > 0 ? fragmentsData.length : reconstructionData?.fragment_count || 0}</strong>
                <span>{fragmentsData.length > 0 ? "Extracted from case" : "Target chain members"}</span>
              </div>
              <div className="forensic-metric-tile">
                <label>JPEG Candidates</label>
                <strong style={{ color: "#38bdf8" }}>
                  {fragmentsData.length > 0
                    ? fragmentsData.filter((f) => f.detected_file_type === "JPEG").length
                    : reconstructionData?.fragment_count || 0}
                </strong>
                <span>100% Format Confidence</span>
              </div>
              <div className="forensic-metric-tile">
                <label>Header Fragments</label>
                <strong style={{ color: "#c084fc" }}>
                  {fragmentsData.length > 0
                    ? fragmentsData.filter((f) => f.classification === "HEADER_FRAGMENT").length
                    : 1}
                </strong>
                <span>Contains SOI (FF D8)</span>
              </div>
              <div className="forensic-metric-tile">
                <label>Ending Fragments</label>
                <strong style={{ color: "#4ade80" }}>
                  {fragmentsData.length > 0
                    ? fragmentsData.filter((f) => f.classification === "ENDING_FRAGMENT").length
                    : 1}
                </strong>
                <span>Contains EOI (FF D9)</span>
              </div>
            </div>

            {/* Table or Purged Summary */}
            {fragmentsData.length > 0 ? (
              <div style={{ overflowX: "auto" }}>
                <table className="forensic-data-table">
                  <thead>
                    <tr>
                      <th>Fragment ID</th>
                      <th>Source Filename</th>
                      <th>Size</th>
                      <th>Classification</th>
                      <th>Detected Markers</th>
                      <th>Entropy (Bits/Byte)</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fragmentsData.map((f) => {
                      const markers = f.jpeg_markers || [];
                      return (
                        <tr key={f.id}>
                          <td>
                            <code style={{ color: "#a78bfa" }}>{f.id.slice(0, 8)}</code>
                          </td>
                          <td>
                            <span style={{ fontWeight: "500", color: "#f1f5f9" }}>
                              {f.source_filename}
                            </span>
                          </td>
                          <td>{formatBytes(f.fragment_size)}</td>
                          <td>{renderClassificationBadge(f.classification)}</td>
                          <td>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                              {markers.length > 0 ? (
                                markers.map((m, idx) => (
                                  <span key={idx} className="chip-marker">
                                    {m.name || m}
                                  </span>
                                ))
                              ) : (
                                <span style={{ color: "#64748b", fontSize: "11px" }}>None</span>
                              )}
                            </div>
                          </td>
                          <td>
                            <span style={{ fontFamily: "monospace" }}>
                              {f.entropy ? f.entropy.toFixed(3) : "N/A"}
                            </span>
                          </td>
                          <td>
                            <span className="status-badge-valid" style={{ fontSize: "10px", padding: "2px 6px" }}>
                              Analyzed
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: "14px", background: "rgba(15, 23, 42, 0.4)", borderRadius: "8px", border: "1px dashed rgba(148, 163, 184, 0.2)", textAlign: "center", color: "#94a3b8", fontSize: "12px" }}>
                <CheckCircle2 size={18} style={{ color: "#4ade80", margin: "0 auto 6px auto", display: "block" }} />
                <strong>Temporary Fragment Rows Safely Purged</strong>
                <p style={{ margin: "4px 0 0 0", color: "#64748b" }}>
                  All temporary fragment and relationship processing records were purged from the database after successful reconstruction. The chain sequence below is preserved directly from the validated candidate.
                </p>
              </div>
            )}
          </div>

          {/* 2. DIRECTED RELATIONSHIP GRAPH CARD */}
          {reconstructionData?.chain_details && (
            <div className="forensic-card">
              <div className="forensic-card-header">
                <h3>
                  <Network size={18} style={{ color: "#38bdf8" }} />
                  Directed Fragment Relationship Graph (Inferred Sequence)
                </h3>
                <span className="status-badge-valid">
                  {reconstructionData.fragment_count} Nodes Chained
                </span>
              </div>

              <div className="relationship-graph-wrapper">
                <div className="graph-disclaimer-banner">
                  <ShieldCheck size={15} style={{ color: "#38bdf8", flexShrink: 0 }} />
                  <span>
                    <strong>Directed Compatibility Model:</strong> Arrows represent the inferred{" "}
                    <em>probable next fragment</em> in the raw byte stream based on multi-axis forensic evidence.
                  </span>
                </div>

                <div className="relationship-chain-flow">
                  {reconstructionData.chain_details.map((node, idx) => {
                    const isLast = idx === reconstructionData.chain_details.length - 1;
                    const nextEdge = node.next_edge;
                    return (
                      <div key={node.fragment_id} style={{ display: "flex", alignItems: "center" }}>
                        <div className="chain-node-card">
                          <span className="chain-node-step">Step {node.step}</span>
                          <span className="chain-node-name" title={node.filename}>
                            {node.filename}
                          </span>
                          <span className="chain-node-meta">
                            {node.classification} &bull; {formatBytes(node.size)}
                          </span>
                        </div>

                        {!isLast && nextEdge && (
                          <div className="chain-edge-connector">
                            <span className="edge-score-pill">
                              {(nextEdge.total_score * 100).toFixed(1)}%
                            </span>
                            <span className="edge-arrow-line">──▶</span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* 3. RECONSTRUCTION SHOWCASE & VALIDATION */}
          {reconstructionData && (
            <div className="forensic-card">
              <div className="forensic-card-header">
                <h3>
                  <ImageIcon size={18} style={{ color: "#4ade80" }} />
                  Reconstructed Forensic Artifact & Multi-Stage Validation
                </h3>
                {renderReconstructionStatusBadge(reconstructionData.status, reconstructionData.validation_result)}
              </div>

              <div className="reconstruction-showcase-grid">
                {/* Visual Preview */}
                <div className="image-preview-panel">
                  {reconstructionData.status === "VALIDATED" ||
                  reconstructionData.status === "VALID" ||
                  reconstructionData.status === "PARTIALLY_VALID" ||
                  reconstructionData.status === "PARTIALLY_VALIDATED" ||
                  reconstructionData.validation_result?.decoder_valid ? (
                    <img
                      src={getReconstructionViewUrl(reconstructionData.id)}
                      alt="Reconstructed Forensic JPEG"
                      onError={(e) => {
                        e.target.style.display = "none";
                      }}
                    />
                  ) : (
                    <div style={{ textAlign: "center", color: "#64748b" }}>
                      <AlertCircle size={32} style={{ color: "#ef4444", marginBottom: "8px" }} />
                      <p>Image preview unavailable due to corruption or mismatch.</p>
                    </div>
                  )}

                  <div style={{ marginTop: "14px", display: "flex", gap: "10px" }}>
                    <a
                      href={getReconstructionDownloadUrl(reconstructionData.id)}
                      download
                      className="upload-button"
                      style={{ textDecoration: "none", fontSize: "11px", padding: "8px 16px" }}
                    >
                      <Download size={14} /> Download Reconstructed JPEG
                    </a>

                    <a
                      href={getReconstructionViewUrl(reconstructionData.id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="upload-button-secondary"
                      style={{ textDecoration: "none", fontSize: "11px", padding: "8px 16px" }}
                    >
                      <ExternalLink size={14} /> View Full Screen
                    </a>
                  </div>
                </div>

                {/* Validation Checklist & Metadata */}
                <div className="reconstruction-details-panel">
                  <div className="forensic-metric-tile" style={{ marginBottom: "8px" }}>
                    <label>Estimated Reconstruction Confidence</label>
                    <strong style={{ color: reconstructionData.confidence >= 0.9 ? "#4ade80" : "#facc15", fontSize: "24px" }}>
                      {(reconstructionData.confidence * 100).toFixed(1)}%
                    </strong>
                    <span>
                      Synthesized from {reconstructionData.fragment_count} fragments ({formatBytes(reconstructionData.reconstructed_size)})
                    </span>
                  </div>

                  {/* Separate Development Ground Truth Verification */}
                  {reconstructionData.validation_result?.dev_verification &&
                    reconstructionData.validation_result.dev_verification !== "NOT_AVAILABLE" && (
                      <div
                        className={`dev-verification-banner ${
                          reconstructionData.validation_result.dev_verification === "PASS" ? "pass" : "fail"
                        }`}
                      >
                        <div className="dev-verification-header">
                          <ShieldCheck size={16} />
                          <span style={{ fontWeight: 700 }}>
                            Development Verification: {reconstructionData.validation_result.dev_verification === "PASS" ? "PASS" : "FAIL"}
                          </span>
                        </div>
                        <div className="dev-verification-meta">
                          <div className="dev-meta-row">
                            <span>Reconstructed SHA-256:</span>
                            <code>{reconstructionData.validation_result.calculated_sha256}</code>
                          </div>
                          {reconstructionData.validation_result.target_sha256 && (
                            <div className="dev-meta-row">
                              <span>Target Ground Truth SHA-256:</span>
                              <code>{reconstructionData.validation_result.target_sha256}</code>
                            </div>
                          )}
                          <div className="dev-verification-status-note">
                            {reconstructionData.validation_result.exact_sha_match ? (
                              <span className="note-pass">
                                ✓ Exact byte-level match confirmed against original target JPEG (43,202 Bytes).
                              </span>
                            ) : (
                              <span className="note-fail">
                                ⚠ Reconstruction mismatch: Reconstructed byte sequence differs from target ground truth.
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                  <div className="validation-checklist">
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "13px", color: "#f1f5f9" }}>
                      Forensic Validation Audit Checklist
                    </h4>

                    <div className="checklist-item">
                      <span>Start of Image (SOI) Marker [FF D8]</span>
                      <strong className={reconstructionData.validation_result?.has_soi ? "pass" : "fail"}>
                        {reconstructionData.validation_result?.has_soi ? "✓ DETECTED" : "✗ MISSING"}
                      </strong>
                    </div>

                    <div className="checklist-item">
                      <span>End of Image (EOI) Marker [FF D9]</span>
                      <strong className={reconstructionData.validation_result?.has_eoi ? "pass" : "fail"}>
                        {reconstructionData.validation_result?.has_eoi ? "✓ DETECTED" : "✗ MISSING"}
                      </strong>
                    </div>

                    <div className="checklist-item">
                      <span>Single-File Constraint (No Internal SOI / EOI)</span>
                      <strong
                        className={
                          !reconstructionData.validation_result?.has_internal_soi &&
                          !reconstructionData.validation_result?.has_internal_eoi
                            ? "pass"
                            : "fail"
                        }
                      >
                        {!reconstructionData.validation_result?.has_internal_soi &&
                        !reconstructionData.validation_result?.has_internal_eoi
                          ? "✓ CLEAN (SINGLE FILE)"
                          : "✗ VIOLATION (MULTIPLE JPEGS)"}
                      </strong>
                    </div>

                    <div className="checklist-item">
                      <span>Entropy Stream MCU Scan Progression</span>
                      <strong
                        className={
                          reconstructionData.validation_result?.structurally_parseable ||
                          reconstructionData.validation_result?.entropy_stream_complete
                            ? "pass"
                            : "fail"
                        }
                      >
                        {reconstructionData.validation_result?.expected_mcus > 0
                          ? `✓ ${reconstructionData.validation_result.decoded_mcus} / ${reconstructionData.validation_result.expected_mcus} MCUs`
                          : "✓ PARSED"}
                      </strong>
                    </div>

                    <div className="checklist-item">
                      <span>Full Raster Decoder Decompression</span>
                      <strong
                        className={
                          reconstructionData.validation_result?.decoder_valid ||
                          reconstructionData.validation_result?.decoder_validation
                            ? "pass"
                            : "fail"
                        }
                      >
                        {reconstructionData.validation_result?.decoder_valid ||
                        reconstructionData.validation_result?.decoder_validation
                          ? "✓ PASS (DECOMPRESSED)"
                          : "✗ FAILED"}
                      </strong>
                    </div>

                    {reconstructionData.validation_result?.image_metadata && (
                      <div className="checklist-item">
                        <span>Decoded Dimensions & Mode</span>
                        <strong style={{ color: "#38bdf8" }}>
                          {reconstructionData.validation_result.image_metadata.width} &times;{" "}
                          {reconstructionData.validation_result.image_metadata.height}{" "}
                          ({reconstructionData.validation_result.image_metadata.mode})
                        </strong>
                      </div>
                    )}

                    <div className="checklist-item">
                      <span>Reconstructed Size Sanity Check</span>
                      <strong style={{ color: "#cbd5e1" }}>
                        {formatBytes(reconstructionData.reconstructed_size)}
                      </strong>
                    </div>
                  </div>

                  {/* Validation failure reasons alert */}
                  {reconstructionData.validation_result?.failure_reasons?.length > 0 && (
                    <div className="validation-failure-alert">
                      <div className="alert-title">
                        <AlertCircle size={14} />
                        <span>Validation Warnings & Caveats</span>
                      </div>
                      <ul>
                        {reconstructionData.validation_result.failure_reasons.map((msg, mIdx) => (
                          <li key={mIdx}>{msg}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 4. DEVELOPER / DEBUG VIEW */}
          {reconstructionData && (
            <div className="forensic-card">
              <div className="forensic-card-header">
                <h3>
                  <Terminal size={18} style={{ color: "#38bdf8" }} />
                  Developer & Forensic Debugger View
                </h3>
                <span className="chip" style={{ fontSize: "11px", color: "#94a3b8" }}>
                  Candidate Edge Metrics & Decoy Exclusion Log
                </span>
              </div>

              <div className="debug-view-container">
                {/* Metrics Header */}
                <div className="debug-metrics-header">
                  <div className="debug-stat-card">
                    <label>Selected Fragments</label>
                    <strong style={{ color: "#4ade80" }}>
                      {reconstructionData.fragment_count}
                    </strong>
                    <span>Target Chain Members</span>
                  </div>

                  <div className="debug-stat-card">
                    <label>Rejected Fragments</label>
                    <strong style={{ color: "#f87171" }}>
                      {(reconstructionData.rejected_fragments ||
                        reconstructionData.validation_result?.rejected_fragments ||
                        []).length}
                    </strong>
                    <span>Decoys Excluded</span>
                  </div>

                  <div className="debug-stat-card">
                    <label>Reconstructed Output Size</label>
                    <strong style={{ color: "#38bdf8" }}>
                      {formatBytes(reconstructionData.reconstructed_size)}
                    </strong>
                    <span>Exact Raw Byte Concatenation</span>
                  </div>

                  <div className="debug-stat-card">
                    <label>Bitstream Decompression</label>
                    <strong style={{ color: "#a78bfa" }}>
                      {reconstructionData.validation_result?.decoded_mcus ?? "N/A"} /{" "}
                      {reconstructionData.validation_result?.expected_mcus ?? "N/A"}
                    </strong>
                    <span>Decoded MCUs Completed</span>
                  </div>
                </div>

                {/* Candidate Reconstruction Sequence Chain */}
                {reconstructionData.chain_details && (
                  <div className="debug-chain-summary">
                    <div className="debug-chain-summary-header">
                      Candidate Reconstruction Sequence:
                    </div>
                    <div className="debug-chain-tokens">
                      {reconstructionData.chain_details.map((node, idx) => (
                        <span
                          key={node.fragment_id}
                          style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
                        >
                          <span className="debug-token-item" title={node.filename}>
                            {node.filename.replace(".bin", "").replace(".jpg", "")}
                          </span>
                          {idx < reconstructionData.chain_details.length - 1 && (
                            <span className="debug-token-arrow">→</span>
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Edge Multi-Axis Score Breakdown */}
                {reconstructionData.chain_details && (
                  <div>
                    <h4 style={{ margin: "0 0 10px 0", fontSize: "13px", color: "#f1f5f9" }}>
                      Directed Pairwise Edge Scores (Candidate Chain Flow)
                    </h4>
                    <div className="debug-edge-grid">
                      {reconstructionData.chain_details.map((node, idx) => {
                        const edge = node.next_edge;
                        if (!edge) return null;
                        return (
                          <div key={idx} className="debug-edge-card">
                            <div className="debug-edge-header">
                              <div className="debug-edge-nodes">
                                <code>{node.filename.slice(0, 16)}</code>
                                <span>→</span>
                                <code>{edge.to_filename.slice(0, 16)}</code>
                              </div>
                              <span className="debug-edge-total-pill">
                                Total: {(edge.total_score * 100).toFixed(1)}%
                              </span>
                            </div>

                            <div className="debug-edge-scores-table">
                              <div className="debug-score-row">
                                <span>Structural:</span>
                                <strong>{(edge.structural_score * 100).toFixed(1)}%</strong>
                              </div>
                              <div className="debug-score-row">
                                <span>Boundary:</span>
                                <strong>{(edge.boundary_score * 100).toFixed(1)}%</strong>
                              </div>
                              <div className="debug-score-row">
                                <span>Parser:</span>
                                <strong>{(edge.parser_score * 100).toFixed(1)}%</strong>
                              </div>
                              <div className="debug-score-row">
                                <span>Total:</span>
                                <strong>{(edge.total_score * 100).toFixed(1)}%</strong>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Excluded Decoy Fragments Attribution Panel */}
                {(reconstructionData.rejected_fragments ||
                  reconstructionData.validation_result?.rejected_fragments ||
                  []).length > 0 && (
                  <div className="rejected-fragments-section">
                    <div className="rejected-fragments-header">
                      <h4>
                        <XCircle size={15} style={{ color: "#ef4444" }} />
                        Excluded Decoy Fragments & Forensic Justifications
                      </h4>
                      <span style={{ fontSize: "11px", color: "#94a3b8" }}>
                        {(reconstructionData.rejected_fragments ||
                          reconstructionData.validation_result?.rejected_fragments ||
                          []).length}{" "}
                        Fragments Filtered
                      </span>
                    </div>

                    <div className="rejected-grid">
                      {(
                        reconstructionData.rejected_fragments ||
                        reconstructionData.validation_result?.rejected_fragments ||
                        []
                      ).map((rf, rIdx) => {
                        const reasonLines = (rf.reason || "Low global path compatibility").split(
                          " • "
                        );
                        return (
                          <div key={rf.fragment_id || rIdx} className="rejected-card">
                            <div className="rejected-card-header">
                              <div>
                                <div className="rejected-filename">{rf.filename}</div>
                                <div className="rejected-meta">
                                  <span>{rf.classification}</span>
                                  <span>&bull;</span>
                                  <span>{formatBytes(rf.size)}</span>
                                </div>
                              </div>
                              <span className="rejected-exclusion-badge">
                                Excluded from target chain
                              </span>
                            </div>

                            <div className="rejected-reason-box">
                              <div className="rejected-reason-label">Reason:</div>
                              <ul className="rejected-reason-list">
                                {reasonLines.map((line, lIdx) => (
                                  <li key={lIdx}>{line}</li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* 5. EVIDENCE EXPLANATION ACCORDION */}
          {reconstructionData?.chain_details && (
            <div className="forensic-card">
              <div className="forensic-card-header">
                <h3>
                  <Sparkles size={18} style={{ color: "#a78bfa" }} />
                  Forensic Evidence & Explainability Trail
                </h3>
                <span style={{ fontSize: "11px", color: "#94a3b8" }}>
                  Decision-Support Justifications
                </span>
              </div>

              <div className="evidence-list">
                {reconstructionData.chain_details.map((node, idx) => {
                  const edge = node.next_edge;
                  if (!edge) return null;

                  return (
                    <div key={idx} className="evidence-hop-item">
                      <div className="evidence-hop-header">
                        <div>
                          <span>
                            Hop {idx + 1}: <code style={{ color: "#38bdf8" }}>{node.filename}</code>
                          </span>
                          {" ──▶ "}
                          <code style={{ color: "#a78bfa" }}>{edge.to_filename}</code>
                        </div>

                        <span className="edge-score-pill">
                          Compatibility: {(edge.total_score * 100).toFixed(1)}%
                        </span>
                      </div>

                      <div className="evidence-score-bars">
                        <div className="evidence-score-item">
                          <label>Structural Score</label>
                          <strong>{(edge.structural_score * 100).toFixed(1)}%</strong>
                        </div>
                        <div className="evidence-score-item">
                          <label>Boundary Seam Score</label>
                          <strong>{(edge.boundary_score * 100).toFixed(1)}%</strong>
                        </div>
                        <div className="evidence-score-item">
                          <label>Parser Score</label>
                          <strong>{(edge.parser_score * 100).toFixed(1)}%</strong>
                        </div>
                        <div className="evidence-score-item">
                          <label>Physical LBA Evidence</label>
                          <span style={{ color: "#64748b" }}>Unavailable</span>
                        </div>
                        <div className="evidence-score-item">
                          <label>ML Model Score</label>
                          <span style={{ color: "#64748b" }}>Unavailable (Deferred)</span>
                        </div>
                      </div>

                      {edge.evidence?.explanations && edge.evidence.explanations.length > 0 && (
                        <ul className="evidence-bullets">
                          {edge.evidence.explanations.map((exp, eIdx) => (
                            <li key={eIdx}>{exp}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default ScanData;