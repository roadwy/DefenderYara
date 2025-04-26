
rule Trojan_Win64_CobaltStrike_RKB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 44 24 07 48 8b 4c 24 10 48 8b 54 24 08 44 0f be 04 11 41 31 c0 44 88 04 11 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}