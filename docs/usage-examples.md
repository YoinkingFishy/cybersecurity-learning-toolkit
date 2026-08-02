# Usage Examples

## Port scanner

Scan a single host for common ports:

`ash
python -m port_scanner.cli --target 192.0.2.10 --ports 22,80,443
`

Scan a range and export CSV:

`ash
python -m port_scanner.cli --target 192.0.2.10 --start-port 1 --end-port 1024 \
  --output results.csv --format csv
`

## Log analyzer

Analyze an Apache log:

`ash
python -m log_analyzer.cli --file examples/sample_apache.log --format apache
`

Analyze an sshd log and export a JSON report:

`ash
python -m log_analyzer.cli --file examples/sample_system.log --format auth \
  --output report.json
`

## File integrity checker

Create a baseline manifest and verify later:

`ash
python -m file_integrity.cli create-manifest examples/*.log --output manifest.json
python -m file_integrity.cli check-manifest manifest.json
`

Hash a single file:

`ash
python -m file_integrity.cli hash examples/sample_apache.log
`
