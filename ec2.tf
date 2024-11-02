resource "aws_iam_role" "minecraft_instance_role" {
  name = "minecraft-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

data "aws_iam_policy_document" "custom_ssm_agent_policy_document" {
  statement {
    effect = "Allow"
    actions = [
      "ssm:SendCommand",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "ssm_policy_attachment" {
  role       = aws_iam_role.minecraft_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_policy_attachment" {
  role       = aws_iam_role.minecraft_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_policy_attachment" {
  role       = aws_iam_role.minecraft_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "default_ssm_policy_attachment" {
  role       = aws_iam_role.minecraft_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy"
}

resource "aws_key_pair" "minecraft_key" {
  key_name   = "minecraft-server-key"  # Name for your key pair
  public_key = file("~/.ssh/id_ed25519.pub")  # Path to your SSH public key
}

resource "aws_instance" "minecraft_server" {
  ami           = "ami-06b21ccaeff8cd686"  # Example AMI for Amazon Linux 2 (update to your preferred AMI)
  instance_type = "t3.xlarge"  # This instance type is recommended for Minecraft

  key_name = aws_key_pair.minecraft_key.key_name

  tags = {
    Name = "Minecraft-Server"
  }

  # Security Group to allow access
  vpc_security_group_ids = [aws_security_group.minecraft_sg.id]

  # Attach IAM Role to instance
  iam_instance_profile = aws_iam_instance_profile.minecraft_instance_profile.name

  # User data script to install Java and start Minecraft server
  user_data = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install -y java-22-amazon-corretto-devel
              sudo yum install -y tmux unzip

              sudo yum install -y amazon-ssm-agent
              sudo systemctl enable amazon-ssm-agent
              sudo systemctl start amazon-ssm-agent

              cd home/ec2-user
              mkdir Minecraft
              cd Minecraft/
              curl -JLO "https://api.feed-the-beast.com/v1/modpacks/public/modpack/126/12530/server/linux"
              chmod +x serverinstall_126_12530
              ./serverinstall_126_12530
              echo -e ".\yes" | ./serverinstall_126_12530
              tmux new -d -s minecraft "echo -e 'yes' | ./start.sh"
              EOF
}

resource "aws_iam_instance_profile" "minecraft_instance_profile" {
  name = "minecraft-instance-profile"
  role = aws_iam_role.minecraft_instance_role.name
}

resource "aws_security_group" "minecraft_sg" {
  name        = "minecraft-sg"
  description = "Allow inbound Minecraft access"
  vpc_id      = "vpc-0123b9d0536e94660"  # Replace with your VPC ID

  ingress {
    description      = "Allow Minecraft TCP"
    from_port        = 25565  # Default Minecraft port
    to_port          = 25565
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]  # Open to the world (change for more security)
  }

  ingress {
    description      = "Allow SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["${var.home_ip}/32"]  # Restrict to your IP address
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "instance_public_ip" {
  value = aws_instance.minecraft_server.public_ip
  description = "Public IP address of the Minecraft server EC2 instance"
}
