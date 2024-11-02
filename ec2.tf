# This Terraform script will create an EC2 instance to host a Minecraft server on AWS.
# Make sure to replace the placeholder values with your own information.

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

  # User data script to install Java and start Minecraft server
  user_data = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install -y java-22-amazon-corretto-devel
              sudo yum install -y tmux unzip

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
