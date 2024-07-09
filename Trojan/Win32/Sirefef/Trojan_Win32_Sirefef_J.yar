
rule Trojan_Win32_Sirefef_J{
	meta:
		description = "Trojan:Win32/Sirefef.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //1 %wZ\Software\%08x
		$a_01_1 = {68 63 6e 63 74 } //1 hcnct
		$a_03_2 = {81 7d 0c 73 65 6e 64 74 ?? 81 7d 0c 72 65 63 76 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Sirefef_J_2{
	meta:
		description = "Trojan:Win32/Sirefef.J,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //1 %wZ\Software\%08x
		$a_01_1 = {68 63 6e 63 74 } //1 hcnct
		$a_03_2 = {81 7d 0c 73 65 6e 64 74 ?? 81 7d 0c 72 65 63 76 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}