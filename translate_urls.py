import csv
from utils.translation_utils import translate_to_khmer


def translate_urls_csv(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        for row in reader:
            if row:
                url = row[0]
                label = row[1] if len(row) > 1 else ''
                translated_url = translate_to_khmer(url)
                writer.writerow([translated_url, label])


if __name__ == "__main__":
    translate_urls_csv('data/sample_urls.csv', 'data/sample_urls_khmer.csv')
    print("URLs translated to Khmer and saved to data/sample_urls_khmer.csv")
