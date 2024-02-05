
rule Trojan_Win32_Gophe_A{
	meta:
		description = "Trojan:Win32/Gophe.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {61 64 64 69 74 69 6f 6e 61 6c 5f 65 6d 61 69 6c 73 } //additional_emails  01 00 
		$a_80_1 = {61 74 74 61 63 68 5f 64 61 74 61 5f 62 61 73 65 36 34 } //attach_data_base64  02 00 
		$a_80_2 = {42 69 74 6e 65 73 73 } //Bitness  01 00 
		$a_80_3 = {63 6c 69 65 6e 74 5f 63 6f 6e 6e 65 63 74 69 6f 6e 5f 69 64 } //client_connection_id  01 00 
		$a_80_4 = {64 6f 77 6e 6c 6f 61 64 5f 75 72 6c } //download_url  01 00 
		$a_80_5 = {66 69 6c 65 5f 64 61 74 61 } //file_data  01 00 
		$a_80_6 = {6d 65 73 73 61 67 65 5f 61 74 74 61 63 68 } //message_attach  01 00 
		$a_80_7 = {4f 75 74 6c 6f 6f 6b 2d 41 64 64 69 74 69 6f 6e 61 6c 2d 41 64 64 72 65 73 73 2d 54 6f 74 61 6c } //Outlook-Additional-Address-Total  01 00 
		$a_80_8 = {4f 75 74 6c 6f 6f 6b 2d 41 64 64 72 65 73 73 2d 54 6f 74 61 6c } //Outlook-Address-Total  01 00 
		$a_80_9 = {4f 75 74 6c 6f 6f 6b 2d 4d 65 73 73 61 67 65 73 2d 43 72 65 61 74 65 64 } //Outlook-Messages-Created  01 00 
		$a_80_10 = {73 65 6e 64 5f 74 6f 5f 61 6c 6c } //send_to_all  03 00 
		$a_03_11 = {8d 70 08 8d 64 24 00 8b f9 c1 ef 1e 33 cf 69 c9 90 01 04 03 ca 89 0e 42 83 c6 04 81 fa 70 02 00 00 7c e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}