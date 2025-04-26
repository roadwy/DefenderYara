
rule Backdoor_Win32_Cakl_gen_B{
	meta:
		description = "Backdoor:Win32/Cakl.gen!B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 06 00 00 00 44 65 6e 65 73 65 } //1
		$a_01_1 = {ff ff ff ff 06 00 00 00 50 6f 72 74 4e 6f } //1
		$a_01_2 = {ff ff ff ff 06 00 00 00 4b 75 72 62 61 6e } //1
		$a_01_3 = {ff ff ff ff 08 00 00 00 50 61 73 73 77 6f 72 64 } //1
		$a_01_4 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //1 msnmsgr.exe
		$a_01_5 = {46 74 70 2f 49 45 2f 46 69 72 65 66 6f 78 2f 4f 75 74 6c 6f 6f 6b 20 50 61 73 73 77 6f 72 64 73 } //1 Ftp/IE/Firefox/Outlook Passwords
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}