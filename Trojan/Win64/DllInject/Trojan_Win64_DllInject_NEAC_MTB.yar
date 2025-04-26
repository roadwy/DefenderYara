
rule Trojan_Win64_DllInject_NEAC_MTB{
	meta:
		description = "Trojan:Win64/DllInject.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c2 83 e0 1f 2b c2 48 98 48 8b 8c 24 00 03 00 00 0f b6 04 01 8b 8c 24 34 03 00 00 33 c8 8b c1 48 63 8c 24 30 03 00 00 48 8b 94 24 28 03 00 00 88 04 0a eb 82 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}