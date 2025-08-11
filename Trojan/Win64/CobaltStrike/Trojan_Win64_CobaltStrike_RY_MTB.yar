
rule Trojan_Win64_CobaltStrike_RY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 08 41 30 14 08 48 8d 51 01 48 89 d1 49 39 d1 75 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_RY_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.RY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}