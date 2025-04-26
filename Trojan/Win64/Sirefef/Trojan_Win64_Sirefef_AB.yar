
rule Trojan_Win64_Sirefef_AB{
	meta:
		description = "Trojan:Win64/Sirefef.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2 } //1
		$a_03_1 = {48 89 04 24 49 c7 c0 00 80 00 00 48 33 d2 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? ff 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_AB_2{
	meta:
		description = "Trojan:Win64/Sirefef.AB,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2 } //1
		$a_03_1 = {48 89 04 24 49 c7 c0 00 80 00 00 48 33 d2 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? ff 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}