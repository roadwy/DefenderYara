
rule Trojan_Win64_Tedy_AK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 33 c4 8b f8 0f 57 c0 0f 11 03 48 89 73 10 48 c7 43 18 0f 00 00 00 c6 03 00 c7 44 24 20 01 00 00 00 4c 8b 6c 24 48 4c 8b 7c 24 30 83 f8 0f 74 1a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}