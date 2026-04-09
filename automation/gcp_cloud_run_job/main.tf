# Terraform Module - Automated Serverless GCP Cloud Run Job + Cloud Scheduler
# Provisions a least-privilege Security Auditor Service Account, Artifact Registry,
# Cloud Run Job, and a weekly Cloud Scheduler cron trigger.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP Project ID where the automated security extractor job will deploy."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "GCP Region for Cloud Run Job and Artifact Registry."
}

variable "cron_schedule" {
  type        = string
  default     = "0 6 * * 1" # Every Monday at 06:00 UTC
  description = "Cron schedule expression for automated execution."
}

variable "image_tag" {
  type        = string
  default     = "latest"
  description = "Docker image tag in Artifact Registry."
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Least-Privilege Security Auditor Service Account
resource "google_service_account" "security_auditor_sa" {
  account_id   = "cloudsec-migration-sa"
  display_name = "Cloud Security Analisys - Automated Security Auditor SA"
  description  = "Read-only auditor service account for multi-cloud security requirements extraction."
}

# Grant Security Reviewer & Viewer roles at Organization/Project level
resource "google_project_iam_member" "sa_security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.security_auditor_sa.email}"
}

resource "google_project_iam_member" "sa_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.security_auditor_sa.email}"
}

# 2. Artifact Registry Repository for Docker Image
resource "google_artifact_registry_repository" "sec_repo" {
  location      = var.region
  repository_id = "cloudsec-repo"
  description   = "Docker repository for Cloud Security Analisys automated extractor image"
  format        = "DOCKER"
}

# 3. Google Cloud Run Job (Serverless Container Execution)
resource "google_cloud_run_v2_job" "security_extractor_job" {
  name     = "cloudsecurity-migration-job"
  location = var.region

  template {
    template {
      service_account = google_service_account.security_auditor_sa.email

      containers {
        image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.sec_repo.repository_id}/cloudsecurity-extractor:${var.image_tag}"

        resources {
          limits = {
            cpu    = "1"
            memory = "1Gi"
          }
        }

        # Run extraction across all 10 Towers
        args = ["--cloud", "GCP", "--domain", "all", "--output-dir", "/app/docs", "--live"]
      }
    }
  }
}

# 4. Google Cloud Scheduler Job (Cron Trigger)
resource "google_cloud_scheduler_job" "cron_trigger" {
  name        = "cloudsecurity-migration-weekly-trigger"
  description = "Dispara semanalmente a extração automatizada de segurança no Cloud Run Job."
  schedule    = var.cron_schedule
  time_zone   = "America/Sao_Paulo"
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.security_extractor_job.name}:run"

    oauth_token {
      service_account_email = google_service_account.security_auditor_sa.email
    }
  }
}

output "cloud_run_job_name" {
  description = "Nome do Cloud Run Job gerado"
  value       = google_cloud_run_v2_job.security_extractor_job.name
}

output "scheduler_job_name" {
  description = "Nome do Cloud Scheduler agendado"
  value       = google_cloud_scheduler_job.cron_trigger.name
}

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analisys Architecture & Requirements Framework
# ==============================================================================
