
rule Trojan_Win64_Tedy_AD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 57 c0 33 c0 0f 11 45 a0 0f 11 45 b0 0f 11 45 c0 0f 11 45 d0 0f 11 45 e0 0f 11 45 f0 0f 11 45 00 4c 89 6d a0 0f 11 45 a8 4c 89 6d b8 48 c7 45 c0 0f 00 00 00 88 45 a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}