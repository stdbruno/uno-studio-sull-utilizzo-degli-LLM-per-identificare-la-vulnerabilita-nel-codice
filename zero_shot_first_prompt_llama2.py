from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from langchain_core.exceptions import OutputParserException
from langchain.output_parsers import ResponseSchema
from langchain.output_parsers import StructuredOutputParser
import os
import json
import openpyxl
import re


def parse_jsonl(jsonl):
    try:
        c_code_list = []
        for line in jsonl.splitlines():  # Split the input into individual lines
            data = json.loads(line)  # Parse each line as a JSON object
            if (
                "func_name" and "func_src_before" in data
            ):  # Check if the key 'func_name' exists
                code = {}
                code[data["func_name"]] = data["func_src_before"]
                c_code_list.append(code)
        return c_code_list
    except json.JSONDecodeError as e:
        raise OutputParserException(f"Error parsing JSONL: {e}") from e


def read_file(file_path):
    print(f"Reading file: {file_path}")
    content = ""
    with open(file_path, "r") as file:
        content = file.read()
    return content


def add_comma_to_braces(string):
    # Find all occurrences of '}' and add a comma except the last one
    parts = string.rsplit("}", 1)

    modified_string = parts[0].replace("}\n", "},\n") + "}"
    return modified_string


def add_comma_to_quotation_marks(string):
    # Find all occurrences of '"' and add a comma except the last one
    parts = string.rsplit('"', 1)

    modified_string = (
        parts[0].replace('"\n\t"', '",\n\t"')
        + '"'
        + (parts[1] if len(parts) > 1 else "")
    )
    return modified_string


def add_row_to_excel(file_path, filename, CWEIDfound, CWENamesfound):
    # Load the existing workbook or create a new one if it doesn't exist
    try:
        workbook = openpyxl.load_workbook(file_path)
    except FileNotFoundError:
        workbook = openpyxl.Workbook()

    # Select the active sheet (usually the first one)
    sheet = workbook.active

    # Append a new row with filename and vulnerabilities
    new_row = [filename, CWEIDfound, CWENamesfound]
    sheet.append(new_row)

    # Save the workbook with the added row
    workbook.save(file_path)


def append_to_file(file_path, content):
    # Open the file in append mode ('a')
    with open(file_path, "a") as file:
        # Append the content to the file
        file.write(content + "\n")


cwe_name_schema = ResponseSchema(
    name="cwe_name", description="This is the name of CWE security vulnerability"
)

cwe_id_schema = ResponseSchema(
    name="cwe_id",
    description="This is the identifier of the CWE security vulnerability",
)


response_schemas = [cwe_id_schema, cwe_name_schema]

# Class to define the output JSON structure that must be parsed
output_parser = StructuredOutputParser.from_response_schemas(response_schemas)

folder_path = "data_train_val/train"  # sostituire con il percorso alla cartella dove si trovano i file sorgenti da analizzare
excel_file_path = "analisi_zeroshot_llama2.xlsx"
# already_done_files = utils.get_files_already_in_excel(excel_file_path)

# Now file_contents is a dictionary where keys are file names and values are the content of each file
# You can access the content of a specific file using file_contents['filename']

# Load the model
llm = Ollama(model="llama2:13b", temperature=0.0)

# Build the prompt template
template = """You are the best tool to identify security vulnerabilities in source code. 
You will be provided with a source code. If it contains any security vulnerabilities,
reply with the name and the CWE identifier of each of the CWE vulnerabilities found.
If the code does not contain any vulnerabilities, write "Not Vulnerable".

Source code: ```{code}``` 

Return the name and the identifier of each CWE security vulnerability found.

{format_instructions}

"""

prompt = PromptTemplate(
    input_variables=["program"],
    template=template,
    partial_variables={"format_instructions": output_parser.get_format_instructions()},
)

# parser = JsonOutputParser(pydantic_object=PromptResult)  # json output parser


chain = LLMChain(llm=llm, prompt=prompt, verbose=False)

# List all files in the folder
files = [
    f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))
]

# Dictionary to store file content with file names as keys
file_contents = {}

# Iterate through each file and read its content
for file_name in files:
    file_path = os.path.join(folder_path, file_name)
    content = read_file(
        file_path
    )  # Read the content of the file and store it in the dictionary
    file_contents[file_name] = content


for file_name, content in file_contents.items():
    # It doesn't compute this file if it's already in the Excel file.
    # if file_name in already_done_files:
    #   print(f"File {file_name} already in {excel_file_path}. Skipped!")
    #  continue

    file_path = os.path.join(folder_path, file_name)

    print(f"FILE ANALYZED: {file_path}")
    append_to_file("output_zero_shot_llama2.txt", f"FILE ANALYZED:{file_path}")

    content_parsed = parse_jsonl(content)

    for code in content_parsed:
        for func_name, func_src_before in code.items():
            # Print the function name and the code
            print(f"Function name: {func_name}")
            print(f"Function code:\n{func_src_before}")
            print("\n\n\n")
            # Prompt to the LLM model
            response = chain.invoke(func_src_before)
            append_to_file("output_zero_shot_llama2.txt", f"LLM Response: {response}")

            # Regular expression pattern to match JSON-formatted dictionary
            pattern = r"```json\n(.+?)\n```"

            # Search for matches in the text
            match = re.search(pattern, response["text"], re.DOTALL)

            # If a match is found, print the matched dictionary
            matched_dict = ""
            if match:
                matched_dict = match.group(1)

            if matched_dict != "":
                partial_result = add_comma_to_quotation_marks(matched_dict)
                final_result = add_comma_to_braces(partial_result)
                print(f"Final result:\n{final_result}")
                print("\n\n\n\n\n\n")
                cwe_list = json.loads("[" + final_result + "]")

                cwe_id_list = []
                cwe_name_list = []
                # Extract CWE IDs and names
                for cwe in cwe_list:
                    cwe_id = cwe["cwe_id"]
                    cwe_id_list.append(cwe_id)
                    cwe_name = cwe["cwe_name"]
                    cwe_name_list.append(cwe_name)

                    if cwe_id is None or cwe_id == "None" or cwe_id == "":
                        print("Not Vulnerable")
                        print("\n\n\n\n\n\n")
                        append_to_file("output_zero_shot_llama2.txt", "Not Vulnerable")
                    else:
                        append_to_file(
                            "output_zero_shot_llama2.txt", f"CWE ID: {cwe_id}"
                        )
                        append_to_file(
                            "output_zero_shot_llama2.txt", f"CWE Name: {cwe_name}"
                        )

                if cwe_id_list == [] or cwe_id_list == ["None"]:
                    add_row_to_excel(
                        excel_file_path,
                        file_path + ": " + func_name,
                        "Not Vulnerable",
                        "Not Vulnerable",
                    )
                else:
                    add_row_to_excel(
                        excel_file_path,
                        file_path + ": " + func_name,
                        str(cwe_id_list),
                        str(cwe_name_list),
                    )
            else:
                print("Not Vulnerable")
                print("\n\n\n\n\n\n")
                append_to_file("output_zero_shot_llama2.txt", "Not Vulnerable")
                add_row_to_excel(
                    excel_file_path,
                    file_path + ": " + func_name,
                    "Not Vulnerable",
                    "Not Vulnerable",
                )
