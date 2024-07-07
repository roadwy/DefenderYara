
rule Backdoor_Win32_VB_CCL{
	meta:
		description = "Backdoor:Win32/VB.CCL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 ec 10 8b 90 01 02 8b d4 b9 08 00 00 00 89 4d 90 01 01 89 45 90 01 01 89 0a 8b 4d 90 01 01 6a 01 6a 43 89 4a 04 8b 90 01 02 89 42 08 8b 45 90 01 01 89 42 0c ff 91 90 01 02 00 00 90 00 } //2
		$a_00_1 = {42 6c 61 63 6b 20 44 72 65 61 6d } //1 Black Dream
		$a_00_2 = {4b 65 79 6c 6f 67 67 65 72 54 69 6d 65 72 } //1 KeyloggerTimer
		$a_00_3 = {42 00 6c 00 61 00 63 00 6b 00 20 00 44 00 72 00 65 00 61 00 6d 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //1 Black Dream\Server\Server.vbp
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}