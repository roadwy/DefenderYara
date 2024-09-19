
rule Trojan_Win64_Tedy_ZW_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f e2 66 0f 61 d3 66 41 0f db c8 66 0f 69 e3 66 0f 61 d4 66 41 0f db d0 66 0f 67 ca 66 0f ef c8 0f 11 } //1
		$a_03_1 = {41 32 54 04 ?? 49 c1 f9 ?? 31 ca 48 c1 f9 ?? 44 31 ca 31 ca 41 88 54 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}