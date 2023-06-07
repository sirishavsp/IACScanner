/* file_and_code_analysis.tf */

/* 3.4.2 Insecure File Permissions
The S3 bucket doesn't have versioning enabled which can lead to unintended data loss.
*/
resource "aws_s3_bucket" "bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  versioning {
    enabled = false
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

/* 3.4.7 Duplicate Code
The same resource block is used more than once, leading to redundant code.
*/
resource "aws_s3_bucket" "duplicate_bucket" {
  bucket = "duplicate_bucket"
  acl    = "private"
}

resource "aws_s3_bucket" "duplicate_bucket_2" {
  bucket = "duplicate_bucket_2"
  acl    = "private"
}

/* 3.4.8 Code Complexity
Complexity increases when different resources are tangled together in a complex dependency chain.
*/
resource "aws_instance" "web" {
  ami           = "${data.aws_ami.ubuntu.id}"
  instance_type = "t2.micro"
  depends_on    = [aws_iam_role_policy.example, aws_s3_bucket.bucket, aws_security_group.allow_http]
}
resource "aws_s3_bucket" "bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  versioning {
    enabled = false
  }
}
