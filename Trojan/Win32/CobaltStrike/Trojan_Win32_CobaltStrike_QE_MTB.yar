
rule Trojan_Win32_CobaltStrike_QE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {48 6f 72 65 6b 47 6c 65 70 57 } //3 HorekGlepW
		$a_81_1 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //3 GetWindowThreadProcessId
		$a_81_2 = {53 65 74 54 69 6d 65 72 } //3 SetTimer
		$a_81_3 = {43 72 65 61 74 65 57 69 6e 64 6f 77 45 78 57 } //3 CreateWindowExW
		$a_81_4 = {50 6f 73 74 54 68 72 65 61 64 4d 65 73 73 61 67 65 57 } //3 PostThreadMessageW
		$a_81_5 = {50 6f 73 74 4d 65 73 73 61 67 65 57 } //3 PostMessageW
		$a_81_6 = {43 72 65 61 74 65 46 69 6c 65 41 } //3 CreateFileA
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}