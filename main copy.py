import os
import shutil

def rename_and_move_tf_files(directory):
    file_counter = 1

    # Create the "modified" directory within the main directory
    modified_directory = os.path.join(directory, "modified")
    os.makedirs(modified_directory, exist_ok=True)

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.tf'):
                file_path = os.path.join(root, file)
                new_file_name = f"Terraform_Test_File_{file_counter}.tf"
                new_file_path = os.path.join(modified_directory, new_file_name)

                os.rename(file_path, new_file_path)
                print(f"Renamed {file} to {new_file_name}")

                file_counter += 1

# Specify the root directory where the Terraform files are located
root_directory = 'Test/Testfiles3/Downloads'

# Call the function to rename and move the Terraform files
rename_and_move_tf_files(root_directory)
