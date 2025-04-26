
rule Trojan_Win32_CymRan_B_MTB{
	meta:
		description = "Trojan:Win32/CymRan.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_03_0 = {2b ce f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8d 0c 40 8b c6 c1 e1 } //2
		$a_01_1 = {61 74 74 61 63 6b 5f 69 64 } //2 attack_id
		$a_01_2 = {45 44 52 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //2 EDR_attacks_path
		$a_01_3 = {63 6e 63 5f 75 72 6c } //2 cnc_url
		$a_01_4 = {63 6e 63 5f 65 6d 61 69 6c } //2 cnc_email
		$a_01_5 = {63 6e 63 5f 63 6f 6e 6e 65 63 74 69 6f 6e 5f 74 6f 6b 65 6e } //2 cnc_connection_token
		$a_01_6 = {6e 65 77 5f 66 69 6c 65 5f 73 65 72 76 65 72 5f 6d 6f 64 65 } //2 new_file_server_mode
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}