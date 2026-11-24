variable "enable_dnssec" {
  description = "Whether to enable DNSSEC in the dynamic-block pass fixture."
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Whether to enable VPC Flow Logs in the dynamic-block pass fixture."
  type        = bool
  default     = true
}

variable "release_channel" {
  default = "REGULAR"
}
