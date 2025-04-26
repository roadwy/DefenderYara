
rule Trojan_Win64_Ulise_GMX_MTB{
	meta:
		description = "Trojan:Win64/Ulise.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 04 24 48 8b 4c 24 28 0f be 04 01 89 44 24 04 8b 04 24 99 b9 3b 00 00 00 f7 f9 8b c2 83 c0 3a 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 20 88 04 0a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}