output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "internet_gateway_id" {
  value = aws_internet_gateway.gw.id
}

output "public_route_table_id" {
  value = aws_route_table.public.id
}

output "private_route_table_id" {
  value = aws_route_table.private.id
}

output "rds_endpoint" {
  description = "The endpoint of the RDS instance"
  value       = aws_db_instance.app_db.address
}

output "dev_nameservers" {
  value       = length(aws_route53_zone.dev_zone) > 0 ? aws_route53_zone.dev_zone[0].name_servers : []
  description = "Nameservers for dev subdomain"
}

output "demo_nameservers" {
  value       = length(aws_route53_zone.demo_zone) > 0 ? aws_route53_zone.demo_zone[0].name_servers : []
  description = "Nameservers for demo subdomain"
}

