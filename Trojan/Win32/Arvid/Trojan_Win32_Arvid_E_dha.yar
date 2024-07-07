
rule Trojan_Win32_Arvid_E_dha{
	meta:
		description = "Trojan:Win32/Arvid.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6e 65 77 2f 63 68 61 6e 67 5f 66 66 6c 61 67 2e 70 68 70 } //1 new/chang_fflag.php
		$a_01_1 = {6e 65 77 2f 61 6c 6c 5f 66 69 6c 65 5f 69 6e 66 6f 2e 70 68 70 } //1 new/all_file_info.php
		$a_01_2 = {6e 65 77 2f 63 68 61 6e 67 5f 66 6c 61 67 2e 70 68 70 } //1 new/chang_flag.php
		$a_01_3 = {6e 65 77 2f 63 68 61 6e 67 5f 72 66 6c 61 67 2e 70 68 70 } //1 new/chang_rflag.php
		$a_01_4 = {6e 65 77 2f 76 69 65 77 5f 66 69 6c 65 5f 6f 72 64 65 72 2e 70 68 70 } //1 new/view_file_order.php
		$a_01_5 = {6e 65 77 2f 76 69 65 77 5f 72 61 6e 64 6f 6d 5f 6f 72 64 65 72 2e 70 68 70 } //1 new/view_random_order.php
		$a_01_6 = {6e 65 77 2f 76 69 65 77 5f 66 6c 61 73 68 5f 66 69 6c 65 73 2e 70 68 70 } //1 new/view_flash_files.php
		$a_01_7 = {6e 65 77 2f 61 64 64 5f 75 73 65 72 2e 70 68 70 } //1 new/add_user.php
		$a_01_8 = {6d 65 64 69 61 68 69 74 65 63 68 2e 69 6e 66 6f } //4 mediahitech.info
		$a_01_9 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 44 69 73 6b 44 72 69 76 65 } //4 SELECT * FROM Win32_DiskDrive
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*4+(#a_01_9  & 1)*4) >=14
 
}