data "aws_iam_policy_document" "image_builder_execution_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["imagebuilder.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "image_builder_execution_role" {
  name               = "image_builder_execution_role"
  assume_role_policy = data.aws_iam_policy_document.image_builder_execution_role.json
}

data "aws_iam_policy_document" "image_builder_execution_policy" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateLaunchTemplateVersion",
      "ec2:DescribeLaunchTemplates",
      "ec2:ModifyLaunchTemplate",
      "ec2:DescribeLaunchTemplateVersions",
    ]
    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:ExportImage",
    ]
    resources = [
      "arn:aws:ec2:*::image/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:ExportImage",
    ]
    resources = [
      "arn:aws:ec2:*:*:export-image-task/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CancelExportTask",
    ]
    resources = [
      "arn:aws:ec2:*:*:export-image-task/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "iam:CreateServiceLinkedRole",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "ssm.amazonaws.com",
        "ec2fastlaunch.amazonaws.com",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:EnableFastLaunch",
    ]
    resources = [
      "arn:aws:ec2:*::image/*",
      "arn:aws:ec2:*:*:launch-template/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "inspector2:ListCoverage",
      "inspector2:ListFindings",
    ]
    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:CreateRepository",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:TagResource",
    ]
    resources = [
      "arn:aws:ecr:*:*:repository/image-builder-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:BatchDeleteImage",
    ]
    resources = [
      "arn:aws:ecr:*:*:repository/image-builder-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ecr:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "events:DeleteRule",
      "events:DescribeRule",
      "events:PutRule",
      "events:PutTargets",
      "events:RemoveTargets",
    ]
    resources = [
      "arn:aws:events:*:*:rule/ImageBuilder-*",
    ]
  }
}

data "aws_iam_policy_document" "image_builder_execution_policy_more" {

  statement {
    effect = "Allow"
    actions = [
      "ec2:RegisterImage",
    ]
    resources = [
      "arn:aws:ec2:*::image/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:RegisterImage",
    ]
    resources = [
      "arn:aws:ec2:*::snapshot/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:RunInstances",
    ]
    resources = [
      "arn:aws:ec2:*::image/*",
      "arn:aws:ec2:*::snapshot/*",
      "arn:aws:ec2:*:*:subnet/*",
      "arn:aws:ec2:*:*:network-interface/*",
      "arn:aws:ec2:*:*:security-group/*",
      "arn:aws:ec2:*:*:key-pair/*",
      "arn:aws:ec2:*:*:launch-template/*",
      "arn:aws:license-manager:*:*:license-configuration:*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:RunInstances",
    ]
    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*:*:instance/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CreatedBy"
      values = [
        "EC2 Image Builder",
        "EC2 Fast Launch",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "iam:PassRole",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values = [
        "ec2.amazonaws.com",
        "ec2.amazonaws.com.cn",
        "vmie.amazonaws.com",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:StopInstances",
      "ec2:StartInstances",
      "ec2:TerminateInstances",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CopyImage",
      "ec2:CreateImage",
      "ec2:CreateLaunchTemplate",
      "ec2:DeregisterImage",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceTypeOfferings",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:ModifyImageAttribute",
      "ec2:DescribeImportImageTasks",
      "ec2:DescribeExportImageTasks",
      "ec2:DescribeSnapshots",
      "ec2:DescribeHosts",
    ]
    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:ModifySnapshotAttribute",
    ]
    resources = [
      "arn:aws:ec2:*::snapshot/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateTags",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values = [
        "RunInstances",
        "CreateImage",
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CreatedBy"
      values = [
        "EC2 Image Builder",
        "EC2 Fast Launch",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateTags",
    ]
    resources = [
      "arn:aws:ec2:*::image/*",
      "arn:aws:ec2:*:*:export-image-task/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateTags",
    ]
    resources = [
      "arn:aws:ec2:*::snapshot/*",
      "arn:aws:ec2:*:*:launch-template/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CreatedBy"
      values = [
        "EC2 Image Builder",
        "EC2 Fast Launch",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "license-manager:UpdateLicenseSpecificationsForResource",
    ]
    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "sns:Publish",
    ]
    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:ListCommands",
      "ssm:ListCommandInvocations",
      "ssm:AddTagsToResource",
      "ssm:DescribeInstanceInformation",
      "ssm:GetAutomationExecution",
      "ssm:StopAutomationExecution",
      "ssm:ListInventoryEntries",
      "ssm:SendAutomationSignal",
      "ssm:DescribeInstanceAssociationsStatus",
      "ssm:DescribeAssociationExecutions",
      "ssm:GetCommandInvocation",
    ]
    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:SendCommand",
    ]
    resources = [
      "arn:aws:ssm:*:*:document/AWS-RunPowerShellScript",
      "arn:aws:ssm:*:*:document/AWS-RunShellScript",
      "arn:aws:ssm:*:*:document/AWSEC2-RunSysprep",
      "arn:aws:s3:::*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:SendCommand",
    ]
    resources = [
      "arn:aws:ec2:*:*:instance/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/CreatedBy"
      values = [
        "EC2 Image Builder",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:StartAutomationExecution",
    ]
    resources = [
      "arn:aws:ssm:*:*:automation-definition/ImageBuilder*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:CreateAssociation",
      "ssm:DeleteAssociation",
    ]
    resources = [
      "arn:aws:ssm:*:*:document/AWS-GatherSoftwareInventory",
      "arn:aws:ssm:*:*:association/*",
      "arn:aws:ec2:*:*:instance/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
      "kms:GenerateDataKeyWithoutPlaintext",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "kms:EncryptionContextKeys"
      values = [
        "aws:ebs:id",
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values = [
        "ec2.*.amazonaws.com",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values = [
        "ec2.*.amazonaws.com",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values = [
        true,
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values = [
        "ec2.*.amazonaws.com",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
    ]
    resources = [
      "arn:aws:iam::*:role/EC2ImageBuilderDistributionCrossAccountRole",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:CreateLogGroup",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:*:*:log-group:/aws/imagebuilder/*",
    ]
  }
}
resource "aws_iam_policy" "execution_role_access_policy" {
  name        = "image_builder_execution_role_access_policy_first"
  description = "Policy to allow Image Builder execute the custom workflow"
  policy      = data.aws_iam_policy_document.image_builder_execution_policy.json
}

resource "aws_iam_policy" "execution_role_access_policy_more" {
  name        = "image_builder_execution_role_access_policy_second"
  description = "Policy to allow Image Builder execute the custom workflow"
  policy      = data.aws_iam_policy_document.image_builder_execution_policy_more.json
}

resource "aws_iam_role_policy_attachment" "ssm_access_policy_attachment" {
  role       = aws_iam_role.image_builder_execution_role.name
  policy_arn = aws_iam_policy.execution_role_access_policy.arn
}

resource "aws_iam_role_policy_attachment" "ssm_access_policy_attachment_more" {
  role       = aws_iam_role.image_builder_execution_role.name
  policy_arn = aws_iam_policy.execution_role_access_policy_more.arn
}
