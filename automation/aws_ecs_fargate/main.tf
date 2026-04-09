# Terraform Module - Automated Serverless AWS ECS Fargate Task + EventBridge Scheduler
# Provisions an ECR Repository, IAM SecurityAuditor Role, ECS Cluster/Task Definition,
# and an EventBridge schedule rule.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Region for ECS Fargate and ECR."
}

variable "cron_expression" {
  type        = string
  default     = "cron(0 6 ? * MON *)" # Every Monday at 06:00 UTC
  description = "EventBridge cron expression."
}

provider "aws" {
  region = var.aws_region
}

# 1. ECR Repository for Docker Image
resource "aws_ecr_repository" "sec_repo" {
  name                 = "cloudsecurity-extractor"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# 2. IAM Role for Fargate Execution & Read-Only Audit
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "CloudSecurityMigration-TaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_exec_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "security_audit_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# 3. ECS Cluster & Fargate Task Definition
resource "aws_ecs_cluster" "sec_cluster" {
  name = "cloudsecurity-migration-cluster"
}

resource "aws_ecs_task_definition" "sec_task" {
  family                   = "cloudsecurity-extractor-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512" # 0.5 vCPU
  memory                   = "1024" # 1 GB
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "cloudsecurity-extractor"
      image     = "${aws_ecr_repository.sec_repo.repository_url}:latest"
      essential = true
      command   = ["--cloud", "AWS", "--domain", "all", "--output-dir", "/app/docs", "--live"]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/cloudsecurity-extractor"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

# 4. CloudWatch Log Group
resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/cloudsecurity-extractor"
  retention_in_days = 365
}

output "ecr_repository_url" {
  description = "URL do Amazon ECR Repository criado"
  value       = aws_ecr_repository.sec_repo.repository_url
}

output "ecs_cluster_name" {
  description = "Nome do ECS Cluster criado"
  value       = aws_ecs_cluster.sec_cluster.name
}

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analisys Architecture & Requirements Framework
# ==============================================================================
