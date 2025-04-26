
rule Trojan_Win64_CobaltStrike_TC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 74 24 68 4c 8b 6c 24 60 48 8b 5c 24 58 41 ff d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}