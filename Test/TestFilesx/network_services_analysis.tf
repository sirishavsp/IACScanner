/* network_and_services_analysis.tf */

/* 3.4.1 Insecure Services in Terraform Configurations
Unsecure protocol 'HTTP' is being used instead of 'HTTPS'.
*/
resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow inbound traffic on HTTP port"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_http_duplicate" {
  name        = "allow_http_duplicate"
  description = "Allow inbound traffic on HTTP port"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

/* 3.4.3 Hardcoded IPs or Domains
Hardcoded IP is used in the security group rule.
*/
resource "aws_security_group_rule" "my_sg_rule" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["192.0.2.0/24"]
}

/* 3.4.4 Unencrypted Network Protocols
Sensitive data might be transferred over the network in plain text.
*/
resource "aws_db_instance" "default" {
  name     = "mydb"
  username = "foo"
  password = "foobar"
  engine   = "mysql"
  publicly_accessible = true
}
