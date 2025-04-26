data "aws_ami" "latest_ubuntu" {
  most_recent = true

  owners = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

data "aws_partition" "current" {}
data "aws_region" "current" {}

resource "aws_imagebuilder_image_recipe" "example" {
  name = "ubuntu-docker"
  #parent_image = data.aws_ami.latest_ubuntu.id
  parent_image = "arn:${data.aws_partition.current.partition}:imagebuilder:${data.aws_region.current.name}:aws:image/amazon-linux-2-x86/x.x.x"
  version      = "1.0.0"

  component {
    component_arn = "arn:aws:imagebuilder:us-east-1:aws:component/docker-ce-linux/1.0.0/1"
  }

}

resource "aws_iam_instance_profile" "example" {
  name = "test_profile"
  role = aws_iam_role.example.name
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "example" {
  name               = "image_builder_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_policy_attachment" {
  role       = aws_iam_role.example.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_imagebuilder_infrastructure_configuration" "example" {
  description                   = "example description"
  instance_profile_name         = aws_iam_instance_profile.example.name
  name                          = "example"
  terminate_instance_on_failure = true
}

resource "aws_imagebuilder_image_pipeline" "example" {
  image_recipe_arn                 = aws_imagebuilder_image_recipe.example.arn
  infrastructure_configuration_arn = aws_imagebuilder_infrastructure_configuration.example.arn
  name                             = "example"

  execution_role = aws_iam_role.image_builder_execution_role.arn

  lifecycle {
    replace_triggered_by = [
      aws_imagebuilder_image_recipe.example
    ]
  }
}