
rule Trojan_Win64_Sirefef_AA{
	meta:
		description = "Trojan:Win64/Sirefef.AA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 46 30 63 6e 63 74 48 89 7e 28 } //1
		$a_01_1 = {c7 47 30 64 69 73 63 48 89 77 28 } //1
		$a_01_2 = {2f 00 7a 00 61 00 2e 00 63 00 65 00 72 00 } //1 /za.cer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win64_Sirefef_AA_2{
	meta:
		description = "Trojan:Win64/Sirefef.AA,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 46 30 63 6e 63 74 48 89 7e 28 } //1
		$a_01_1 = {c7 47 30 64 69 73 63 48 89 77 28 } //1
		$a_01_2 = {2f 00 7a 00 61 00 2e 00 63 00 65 00 72 00 } //1 /za.cer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}