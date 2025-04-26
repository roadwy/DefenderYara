
rule PWS_Win32_Qusar_RC_{
	meta:
		description = "PWS:Win32/Qusar.RC!!Qusar.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {5f 6c 6f 67 69 6e 73 2e 74 78 74 } //1 _logins.txt
		$a_81_1 = {5f 63 63 64 61 74 61 2e 74 78 74 } //1 _ccdata.txt
		$a_81_2 = {5f 63 6f 6f 6b 69 65 2e 74 78 74 } //1 _cookie.txt
		$a_81_3 = {49 6d 61 67 65 47 72 61 62 } //1 ImageGrab
		$a_81_4 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c } //1 \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
		$a_81_5 = {2f 41 70 70 44 61 74 61 2f 4c 6f 63 61 6c 2f 62 72 6f 77 73 65 72 73 2f 74 78 74 2f } //1 /AppData/Local/browsers/txt/
		$a_81_6 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 64 65 62 75 67 2e 7a 69 70 } //1 \AppData\Local\debug.zip
		$a_81_7 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 62 72 6f 77 73 65 72 73 5c 73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //1 \AppData\Local\browsers\screenshot.png
		$a_81_8 = {2f 44 65 73 6b 74 6f 70 2f 2a 2e 74 78 74 } //1 /Desktop/*.txt
		$a_81_9 = {62 72 6f 77 73 65 72 5f 63 68 72 6f 6d 65 } //1 browser_chrome
		$a_81_10 = {62 72 6f 77 73 65 72 5f 66 6f 6c 64 65 72 } //1 browser_folder
		$a_81_11 = {70 72 6f 66 69 6c 65 5f 66 6f 6c 64 65 72 } //1 profile_folder
		$a_81_12 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 } //1 card_number_encrypted
		$a_81_13 = {62 69 6c 6c 69 6e 67 5f 61 64 64 72 65 73 73 5f 69 64 } //1 billing_address_id
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}