provider "aws" {
  region = "ap-south-1"
  profile = "bobby"
}
resource "tls_private_key" "key1" {
 algorithm = "RSA"
 rsa_bits = 4096
}
resource "local_file" "key2" {
 content = "${tls_private_key.key1.private_key_pem}"
 filename = "task1_key.pem"
 file_permission = 0400
}
resource "aws_key_pair" "key3" {
 key_name = "task1_key"
 public_key = "${tls_private_key.key1.public_key_openssh}"
}
resource "aws_security_group" "bobbySG" {
  name        = "bobbySG"
  description = "Allow TLS inbound traffic"
  


  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Name = "bobbySG"
  }
}
resource "aws_instance" "web" {


depends_on = [
    aws_security_group.bobbySG,
  ]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = "task1_key"
  security_groups = [ "bobbySG" ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = "${tls_private_key.key1.private_key_pem}"
    host     = "${aws_instance.web.public_ip}"
  }


  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }


  tags = {
    Name = "Task2_OS"
  }
}
resource "aws_efs_file_system" "task2efs" {
	  depends_on = [
	    aws_instance.web
	  ]
      creation_token = "volume"
      tags = {
          Name = "task2_efs"
      }
      }

resource "aws_efs_mount_target" "alpha" {
    depends_on = [aws_efs_file_system.task2efs
    ]
    file_system_id = "${aws_efs_file_system.task2efs.id}"
    subnet_id = aws_instance.web.subnet_id
    security_groups = [aws_security_group.bobbySG.id]
}
resource "null_resource" "null2" {
  provisioner "local-exec" {
    command = "echo ${aws_instance.web.private_ip} > public_ip.txt"
  }
}
resource "null_resource" "null3" {
  depends_on = [
    aws_efs_mount_target.alpha
  ]
  connection {
    type = "ssh"
    user = "ec2-user"
    private_key = "${tls_private_key.key1.private_key_pem}"
    host = "${aws_instance.web.public_ip}"

  }
  provisioner "remote-exec" {
    inline = [
      "sudo mount -t ${aws_efs_file_system.task2efs.id}:/ /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/Bobby8249/hybrid-cloud-task2 /var/www/html/"
    ]
  
  }
}

/// Creating S3 bucket
	resource "aws_s3_bucket" "task2s3" {
	  bucket = "task2s3bucket"
	  acl    = "private"
	  tags = {
	    Name = "task2_s3"
	  }
	}
	locals {
	  s3_origin_id = "myS3Origin"
	}
	output "task2s3" {
	  value = aws_s3_bucket.task2s3
	}
	

	

	// Creating Origin Access Identity
	resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
	  comment = "Some comment"
	}
	output "origin_access_identity" {
	  value = aws_cloudfront_origin_access_identity.origin_access_identity
	}
	

	

	// Creating bucket policy
	 data "aws_iam_policy_document" "s3_policy" {
	  statement {
	    actions   = ["s3:GetObject"]
	    resources = ["${aws_s3_bucket.task2s3.arn}/*"]
	    principals {
	      type        = "AWS"
	      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
	    }
	  }
	  statement {
	    actions   = ["s3:ListBucket"]
	    resources = ["${aws_s3_bucket.task2s3.arn}"]
	    principals {
	      type        = "AWS"
	      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
	    }
	  }
	}
	resource "aws_s3_bucket_policy" "example" {
	  bucket = aws_s3_bucket.task2s3.id
	  policy = data.aws_iam_policy_document.s3_policy.json
	}
	resource "aws_cloudfront_distribution" "s3_distribution" {
    origin {
      domain_name = aws_s3_bucket.task2s3.bucket_regional_domain_name
      origin_id = local.s3_origin_id
      s3_origin_config {
        origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
      }
    }
    enabled = true
    is_ipv6_enabled = true
    default_cache_behavior {
      allowed_methods = ["GET","HEAD"]
      cached_methods = ["GET","HEAD"]
      target_origin_id = local.s3_origin_id
      forwarded_values {
        query_string = true
        cookies {
          forward = "none"
        }
      }
      viewer_protocol_policy = "redirect-to-https"
      min_ttl = 0
      default_ttl = 3600
      max_ttl = 86400
    }
    restrictions {
      geo_restriction {
        restriction_type = "none"
      }
    }
    viewer_certificate {
      cloudfront_default_certificate = true
    }
  }
resource "null_resource" "null4" {
  provisioner "local-exec" {
    command = "aws s3 cp D:/HTML Web pages/anonymous.jpg s3://task2s3bucket --acl public-read"  
  }
}