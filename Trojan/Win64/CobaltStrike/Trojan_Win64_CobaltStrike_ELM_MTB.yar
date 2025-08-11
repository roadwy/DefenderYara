
rule Trojan_Win64_CobaltStrike_ELM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ELM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 44 8a 0c 01 48 8b 44 24 08 44 32 0c 02 45 0f b6 c9 44 0b 4c 24 04 4c 8b 54 24 08 49 83 c2 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}