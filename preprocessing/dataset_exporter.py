import csv


class DatasetExporter:

    def export_dataset(self, data, fields, output):

        with open(output, "w", newline="") as f:
            writer = csv.writer(f)

            # header
            header = ["flow_id"]

            
            header += list(fields,)

            writer.writerow(header)
            
            writer.writerows(data)

        print("Dataset extracted")

    def export_dataset_by_stage(self,protocol,data, fields,stages):
        if stages:
            for s in stages:
                with open(f"dataset/{protocol}_{s}_sequences_dataset.csv", "w", newline="") as f:

                    writer = csv.writer(f)

                    # header
                    header = ["flow_id"]

                    
                    header += list(fields,)

                    writer.writerow(header)
                    
                    writer.writerows(data[s])

                print(f"{protocol} {s} dataset extracted")