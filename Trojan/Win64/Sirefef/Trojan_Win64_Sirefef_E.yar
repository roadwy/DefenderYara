
rule Trojan_Win64_Sirefef_E{
	meta:
		description = "Trojan:Win64/Sirefef.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2 } //1
		$a_01_1 = {63 6c 69 63 6b 5f 73 68 65 6c 6c 2e 64 6c 6c } //1 click_shell.dll
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 3d 00 00 00 16 00 18 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_E_2{
	meta:
		description = "Trojan:Win64/Sirefef.E,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2 } //1
		$a_01_1 = {63 6c 69 63 6b 5f 73 68 65 6c 6c 2e 64 6c 6c } //1 click_shell.dll
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 3d 00 00 00 16 00 18 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}