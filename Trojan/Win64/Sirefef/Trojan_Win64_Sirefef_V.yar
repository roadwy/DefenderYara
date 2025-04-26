
rule Trojan_Win64_Sirefef_V{
	meta:
		description = "Trojan:Win64/Sirefef.V,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 d8 8b 43 08 0d 20 20 20 00 3d 60 60 60 00 74 21 3d 63 66 67 00 74 0c 3d 67 6f 69 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Sirefef_V_2{
	meta:
		description = "Trojan:Win64/Sirefef.V,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 d8 8b 43 08 0d 20 20 20 00 3d 60 60 60 00 74 21 3d 63 66 67 00 74 0c 3d 67 6f 69 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}