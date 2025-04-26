
rule Backdoor_Win32_Ixeshe_A_dha{
	meta:
		description = "Backdoor:Win32/Ixeshe.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 bc 4d c6 45 bd 41 c6 45 be 49 c6 45 bf 4c c6 45 c0 5f } //1
		$a_01_1 = {35 65 37 65 38 31 30 30 00 00 00 00 25 73 00 00 25 77 73 00 25 78 00 } //1
		$a_01_2 = {8a 1c 03 30 1c 2f 8b 5c 24 24 47 3b fb 0f 82 } //1
		$a_03_3 = {b9 08 00 00 00 b8 ae ae ae ae 8d [0-09] f3 ab } //1
		$a_03_4 = {b9 e1 04 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa c6 85 ?? ?? ff ff 27 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}