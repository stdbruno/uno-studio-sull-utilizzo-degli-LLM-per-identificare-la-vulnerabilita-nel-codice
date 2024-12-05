import collections
import openpyxl
import re
import cwe_hierarchy_retriever

VULN_INFO = cwe_hierarchy_retriever.get_cwes()
cwe_id_pattern = re.compile(r"CWE-\d+")
cwe_id_filename_pattern = re.compile(r"cwe-\d+")
# cve_id_pattern = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


class FileResult:

    def __init__(self, file_name, matches_exactly, matches_related, found, present):
        self.file_name = file_name
        self.matches_exactly = matches_exactly
        self.matches_related = matches_related
        self.found = found
        self.present = present


def read_data(excel_file_name):
    workbook = openpyxl.load_workbook(excel_file_name)
    sheet = workbook.active

    data = sheet["A:C"]
    data_list = {}
    for i in range(1, len(data[0])):
        data_list[data[0][i].value] = {
            "found": data[1][i].value,
            "CWEs present": data[2][i].value,
            # "CVEs present": data[3][i].value
        }
    return data_list


def parse_data(vuln_dict):
    global VULN_INFO, cwe_id_pattern

    result_list = []
    for fn in vuln_dict.keys():
        cwes = [cwe.upper() for cwe in re.findall(cwe_id_filename_pattern, fn)]
        for i in range(len(cwes)):
            if cwes[i] == "CWE-022":
                cwes[i] = "CWE-22"
            elif cwes[i] == "CWE-078":
                cwes[i] = "CWE-78"
            elif cwes[i] == "CWE-079":
                cwes[i] = "CWE-79"
            elif cwes[i] == "CWE-089":
                cwes[i] = "CWE-89"
        found = re.findall(cwe_id_pattern, vuln_dict[fn]["found"])
        # cves = re.findall(cve_id_pattern, vuln_dict[fn]["CVEs present"])

        """
        for cve in cves:
            for v in VULN_INFO.keys():
                if cve in VULN_INFO[v].cve_list:
                    cwes.append(re.findall(cwe_id_pattern, v)[0])
        del cves
        """

        # create a copy of CWE present list with the CWE categories replaced by their members
        # cwes_cat_flat = []
        # for c in cwes:
        #     if c in VULN_INFO.keys():
        #         vuln = VULN_INFO[c]
        #         if vuln.category is True:
        #             members = [x for x in vuln.parents]
        #             cwes_cat_flat.extend(members)
        #         else:
        #             cwes_cat_flat.append(c)

        # remove duplicates
        # found = list(set(found))
        # cwes = list(set(cwes))
        # cwes_cat_flat = list(set(cwes_cat_flat))

        # collect vulnerabilities that match exactly
        matches = [f for f in found if f in cwes]

        # build the list of present related CWE
        related = []
        for cwe in cwes:
            v = VULN_INFO[cwe]
            for x in list(v.parents) + list(v.children) + list(v.peers):
                related.append(x)

        # collect vulnerabilities that match relatively
        related_cwes = [f for f in found if f in related]

        result = FileResult(
            file_name=fn,
            matches_exactly=matches,
            matches_related=related_cwes,
            found=found,
            present=cwes,
        )
        result_list.append(result)

    return result_list


# just_cwe parameter can be "Not Vulnerable", "022", "078", "079", "089", "125", "190", "416", "476", "787"
def compute_precision_recall(data, exact_value_only=True, just_cwe=None):
    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    cwe022_members = [x for x in VULN_INFO["CWE-22"].parents]
    cwe078_members = [x for x in VULN_INFO["CWE-78"].parents]
    cwe079_members = [x for x in VULN_INFO["CWE-79"].parents]
    cwe089_members = [x for x in VULN_INFO["CWE-89"].parents]
    cwe125_members = [x for x in VULN_INFO["CWE-125"].parents]
    cwe190_members = [x for x in VULN_INFO["CWE-190"].parents]
    cwe416_members = [x for x in VULN_INFO["CWE-416"].parents]
    cwe476_members = [x for x in VULN_INFO["CWE-476"].parents]
    cwe787_members = [x for x in VULN_INFO["CWE-787"].parents]

    for item in data:
        # print(f"File Name: {item.file_name}")
        # print(f"Matches exactly: {item.matches_exactly}")
        # print(f"Matches related: {item.matches_related}")
        # print(f"Found: {item.found}")
        # print(f"Present: {item.present}")
        # choose if compare exact matches or related matches
        if exact_value_only:
            cwe022_valid = ["CWE-22"]
            cwe078_valid = ["CWE-78"]
            cwe079_valid = ["CWE-79"]
            cwe089_valid = ["CWE-89"]
            cwe125_valid = ["CWE-125"]
            cwe190_valid = ["CWE-190"]
            cwe416_valid = ["CWE-416"]
            cwe476_valid = ["CWE-476"]
            cwe787_valid = ["CWE-787"]

            match_values = item.matches_exactly
        else:
            cwe022_valid = []
            cwe022_valid.extend(cwe022_members)
            for m in cwe022_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-22"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe022_valid.append(x)

            cwe078_valid = []
            cwe078_valid.extend(cwe078_members)
            for m in cwe078_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-78"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe078_valid.append(x)

            cwe079_valid = []
            cwe079_valid.extend(cwe079_members)
            for m in cwe079_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-79"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe079_valid.append(x)

            cwe089_valid = []
            cwe089_valid.extend(cwe089_members)
            for m in cwe089_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-89"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe089_valid.append(x)

            cwe125_valid = []
            cwe125_valid.extend(cwe125_members)
            for m in cwe125_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-125"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe125_valid.append(x)

            cwe190_valid = []
            cwe190_valid.extend(cwe190_members)
            for m in cwe190_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-190"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe190_valid.append(x)

            cwe416_valid = []
            cwe416_valid.extend(cwe416_members)
            for m in cwe416_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-416"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe416_valid.append(x)

            cwe476_valid = []
            cwe476_valid.extend(cwe476_members)
            for m in cwe476_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-476"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe476_valid.append(x)

            cwe787_valid = []
            cwe787_valid.extend(cwe787_members)
            for m in cwe787_members:
                v = VULN_INFO[m]
                for x in (
                    ["CWE-787"] + list(v.parents) + list(v.children) + list(v.peers)
                ):
                    cwe787_valid.append(x)

            match_values = item.matches_related + item.matches_exactly

        # prepare the list of matches, present and found for the CWEs specified
        # it's a kind of filtering the CWE values we don't care
        if just_cwe == "22":
            matches = [x for x in match_values if x in cwe022_valid]
            present = [x for x in item.present if x == "CWE-22"]
            found = [x for x in item.found if x in cwe022_valid]
        elif just_cwe == "78":
            matches = [x for x in match_values if x in cwe078_valid]
            present = [x for x in item.present if x == "CWE-78"]
            found = [x for x in item.found if x in cwe078_valid]
        elif just_cwe == "79":
            matches = [x for x in match_values if x in cwe079_valid]
            present = [x for x in item.present if x == "CWE-79"]
            found = [x for x in item.found if x in cwe079_valid]
        elif just_cwe == "89":
            matches = [x for x in match_values if x in cwe089_valid]
            present = [x for x in item.present if x == "CWE-89"]
            found = [x for x in item.found if x in cwe089_valid]
        elif just_cwe == "125":
            matches = [x for x in match_values if x in cwe125_valid]
            present = [x for x in item.present if x == "CWE-125"]
            found = [x for x in item.found if x in cwe125_valid]
        elif just_cwe == "190":
            matches = [x for x in match_values if x in cwe190_valid]
            present = [x for x in item.present if x == "CWE-190"]
            found = [x for x in item.found if x in cwe190_valid]
        elif just_cwe == "416":
            matches = [x for x in match_values if x in cwe416_valid]
            present = [x for x in item.present if x == "CWE-416"]
            found = [x for x in item.found if x in cwe416_valid]
        elif just_cwe == "476":
            matches = [x for x in match_values if x in cwe476_valid]
            present = [x for x in item.present if x == "CWE-476"]
            found = [x for x in item.found if x in cwe476_valid]
        elif just_cwe == "787":
            matches = [x for x in match_values if x in cwe787_valid]
            present = [x for x in item.present if x == "CWE-787"]
            found = [x for x in item.found if x in cwe787_valid]
        elif just_cwe == "Not Vulnerable":
            matches = [
                x
                for x in match_values
                if x
                not in cwe022_valid
                + cwe078_valid
                + cwe079_valid
                + cwe089_valid
                + cwe125_valid
                + cwe190_valid
                + cwe416_valid
                + cwe476_valid
                + cwe787_valid
            ]
            present = [
                x
                for x in item.present
                if x
                not in cwe022_valid
                + cwe078_valid
                + cwe079_valid
                + cwe089_valid
                + cwe125_valid
                + cwe190_valid
                + cwe416_valid
                + cwe476_valid
                + cwe787_valid
            ]
            found = [
                x
                for x in item.found
                if x
                not in cwe022_valid
                + cwe078_valid
                + cwe079_valid
                + cwe089_valid
                + cwe125_valid
                + cwe190_valid
                + cwe416_valid
                + cwe476_valid
                + cwe787_valid
            ]
        else:
            matches = match_values
            present = item.present
            found = item.found

        # compute TP, TN, FP, FN
        if len(present) > 0:
            if len(matches) > 0:
                true_positive += 1
            else:
                false_negative += 1
        else:
            if len(found) > 0:
                false_positive += 1
            else:
                true_negative += 1

    print(
        f"TP: {true_positive}",  # presenti e rilevati
        f"TN: {true_negative}",  # assenti e non rilevati
        f"FP: {false_positive}",  # assenti ma rilevati
        f"FN: {false_negative}",  # presenti ma non rilevati
    )

    # compute metrics
    if true_positive + false_positive == 0:
        precision = 0
    else:
        precision = true_positive / (true_positive + false_positive)
    if true_positive + false_negative == 0:
        recall = 0
    else:
        recall = true_positive / (true_positive + false_negative)
    if true_positive + true_negative + false_negative + false_positive == 0:
        accuracy = 0
    else:
        accuracy = (true_positive + true_negative) / (
            true_positive + true_negative + false_negative + false_positive
        )
    return precision, recall, accuracy


def compute_f1(precision, recall):
    if precision + recall == 0:
        return 0
    return 2 * ((precision * recall) / (precision + recall))


if __name__ == "__main__":
    files = {"analisi_zeroshot_llama2.xlsx": "llama2:13b (ZS)"}

    # statistics about most the CWE present
    cwe_numbers_in_files = {}
    present_cwe_freq_map = {}
    rows = read_data(list(files.keys())[0])
    result = parse_data(rows)
    for cwe in result:
        present_str = str(len(cwe.present))
        if present_str in cwe_numbers_in_files:
            cwe_numbers_in_files[present_str] += 1
        else:
            cwe_numbers_in_files[present_str] = 1
        for p in cwe.present:
            if p in present_cwe_freq_map:
                present_cwe_freq_map[p] += 1
            else:
                present_cwe_freq_map[p] = 1
    print(
        f"FILES BY CWE NUMBER: {dict(sorted(cwe_numbers_in_files.items(), key=lambda item: item[1], reverse=True))}"
    )
    print(
        f"MOST PRESENT CWE: {dict(sorted(present_cwe_freq_map.items(), key=lambda item: item[1], reverse=True))}"
    )
    print()

    # statistics about the CWE found
    for f in files.keys():
        found_cwe_freq_map = {}
        cwe_numbers_in_files = {}

        rows = read_data(f)
        result = parse_data(rows)
        for cwe in result:
            found_str = str(len(cwe.found))
            if found_str in cwe_numbers_in_files:
                cwe_numbers_in_files[found_str] += 1
            else:
                cwe_numbers_in_files[found_str] = 1
            for ff in cwe.found:
                if ff in found_cwe_freq_map:
                    found_cwe_freq_map[ff] += 1
                else:
                    found_cwe_freq_map[ff] = 1

        # exact matches for CWE-022
        precision, recall, _ = compute_precision_recall(result, just_cwe="22")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-22 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-78
        precision, recall, _ = compute_precision_recall(result, just_cwe="78")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-78 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-79
        precision, recall, _ = compute_precision_recall(result, just_cwe="79")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-79 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-89
        precision, recall, _ = compute_precision_recall(result, just_cwe="89")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-89 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-125
        precision, recall, _ = compute_precision_recall(result, just_cwe="125")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-125 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-190
        precision, recall, _ = compute_precision_recall(result, just_cwe="190")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-190 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-416
        precision, recall, _ = compute_precision_recall(result, just_cwe="416")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-416 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-476
        precision, recall, _ = compute_precision_recall(result, just_cwe="476")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-476 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for CWE-787
        precision, recall, _ = compute_precision_recall(result, just_cwe="787")
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of CWE-787 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for All "Not Vulnerable" CWEs
        # TODO gestire anche questo caso
        precision, recall, _ = compute_precision_recall(
            result, just_cwe="Not Vulnerable"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of Not Vulnerable CWEs for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # exact matches for All CWEs
        precision, recall, _ = compute_precision_recall(result)
        f1 = compute_f1(precision, recall)
        print(
            f"EXACT MATCHES of ALL CWEs for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-22
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="22"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-22 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-78
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="78"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-78 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-79
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="79"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-79 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-89
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="89"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-89 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-125
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="125"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-125 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-190
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="190"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-190 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-416
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="416"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-416 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-476
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="476"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-476 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for CWE-787
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="787"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of CWE-787 for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for All "Not Vulnerable" CWEs
        precision, recall, _ = compute_precision_recall(
            result, exact_value_only=False, just_cwe="Not Vulnerable"
        )
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of Not Vulnerable CWEs for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )

        # related matches for All CWEs
        precision, recall, _ = compute_precision_recall(result, exact_value_only=False)
        f1 = compute_f1(precision, recall)
        print(
            f"RELATED MATCHES of ALL CWEs for {files[f]}:\n\tPrecision: {precision}\n\tRecall: {recall}\n\tF1 score: {f1}"
        )
        print(
            f"FILES BY CWE NUMBER: {dict(sorted(cwe_numbers_in_files.items(), key=lambda item: item[1], reverse=True))}"
        )
        print(
            f"MOST FOUND CWE: {dict(sorted(found_cwe_freq_map.items(), key=lambda item: item[1], reverse=True))}"
        )
        print("-------------------------------------------------")
