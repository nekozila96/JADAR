def generate_email(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()

        emails = []
        for line in lines:
            line = line.strip()
            if line:
                # Thay đổi dấu tab thành dấu cách, xóa số thứ tự và các dấu ký tự đặc biệt
                line = line.replace('\t', ' ')
                line = ' '.join(line.split()[1:]) if line.split()[0].isdigit() else line
                line = ''.join(char for char in line if char.isalnum() or char.isspace())

                # Tách mã số sinh viên, họ tên
                parts = line.split(maxsplit=3)
                if len(parts) == 4:
                    student_id = parts[0]
                    full_name = parts[1:]

                    # Tách họ, tên đệm và tên
                    last_name = full_name[0]
                    middle_name = full_name[1:-1]
                    first_name = full_name[-1]

                    # Tạo phần email
                    name_part = first_name.lower() + ''.join([word[0].lower() for word in middle_name + [last_name]])
                    email = f"{name_part}{student_id.lower()}@fpt.edu.vn"
                    emails.append(email)

        # Ghi kết quả vào file đầu ra
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.write("\n".join(emails))

        print(f"Chuyển đổi hoàn tất! Kết quả được lưu trong file: {output_file}")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

# Sử dụng chương trình
input_file = "input.txt"  # Thay bằng tên file txt của bạn
output_file = "output.txt"  # File đầu ra chứa danh sách email
generate_email(input_file, output_file)
