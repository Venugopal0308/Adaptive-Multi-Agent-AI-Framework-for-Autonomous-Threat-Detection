# Local telemetry datasets

The raw CSV and ZIP files in this folder are intentionally excluded from source
control because they are large and their redistribution terms are not established
by this project.

Obtain datasets through an authorized source and verify the applicable license
and citation requirements before including them with any submission. For the
current application, place `label_traffic.csv` here to enable model training and
record analysis. To regenerate the prepared RCA lineage, also provide the
accounting and system-log CSVs expected by `src/pipeline.py`.

Never place credentials, private production logs, or other sensitive data here.
