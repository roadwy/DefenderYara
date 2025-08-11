
rule Trojan_Win64_Tedy_STAO_MTB{
	meta:
		description = "Trojan:Win64/Tedy.STAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 81 ec e0 06 00 00 0f 29 70 c8 0f 29 78 b8 44 0f 29 40 a8 44 0f 29 48 98 48 8b 05 01 c5 00 00 48 33 c4 48 89 85 90 05 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}