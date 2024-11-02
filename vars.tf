variable "environment" {
  type = string
  default = "dev"
}

variable "home_ip" {
  type = string
  sensitive = true
}