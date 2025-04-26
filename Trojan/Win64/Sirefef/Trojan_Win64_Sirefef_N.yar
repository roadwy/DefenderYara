
rule Trojan_Win64_Sirefef_N{
	meta:
		description = "Trojan:Win64/Sirefef.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 47 4e 4f 4c 31 45 00 d1 c0 48 83 c5 04 83 c1 ff 75 f2 } //1
		$a_00_1 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //1 %wZ\Software\%08x
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_N_2{
	meta:
		description = "Trojan:Win64/Sirefef.N,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 47 4e 4f 4c 31 45 00 d1 c0 48 83 c5 04 83 c1 ff 75 f2 } //1
		$a_00_1 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //1 %wZ\Software\%08x
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}