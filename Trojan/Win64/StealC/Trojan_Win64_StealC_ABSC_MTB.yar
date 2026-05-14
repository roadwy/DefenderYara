
rule Trojan_Win64_StealC_ABSC_MTB{
	meta:
		description = "Trojan:Win64/StealC.ABSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 0f be 00 89 44 24 2c 33 d2 48 8b 44 24 20 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f be c0 05 ?? ?? ?? ?? 8b 4c 24 2c 33 c8 8b c1 0f b6 d0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}