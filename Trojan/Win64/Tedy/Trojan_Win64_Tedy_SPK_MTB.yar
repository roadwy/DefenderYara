
rule Trojan_Win64_Tedy_SPK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 11 84 24 c0 00 00 00 0f 11 44 24 50 f2 0f 10 05 90 01 04 f2 0f 11 84 24 f0 00 00 00 0f 10 05 90 01 04 0f 11 8c 24 e0 00 00 00 0f 10 0d 90 01 04 0f 11 84 24 00 01 00 00 0f 10 05 90 01 04 0f 11 8c 24 10 01 00 00 0f 11 84 24 20 01 00 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}