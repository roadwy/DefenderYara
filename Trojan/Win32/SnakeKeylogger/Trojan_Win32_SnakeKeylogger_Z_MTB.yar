
rule Trojan_Win32_SnakeKeylogger_Z_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 6e 61 6b 65 4b 65 79 6c 6f 67 67 65 72 } //1 SnakeKeylogger
		$a_81_1 = {73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d } //1 sendMessage?chat_id=
		$a_81_2 = {73 65 6e 64 44 6f 63 75 6d 65 6e 74 3f 63 68 61 74 5f 69 64 } //1 sendDocument?chat_id
		$a_81_3 = {53 63 72 65 65 6e 73 68 6f 74 } //1 Screenshot
		$a_81_4 = {4b 65 79 73 74 72 6f 6b 65 73 } //1 Keystrokes
		$a_81_5 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 } //1 api.telegram.org
		$a_81_6 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 software\microsoft\windows\currentversion\run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}