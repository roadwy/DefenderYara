
rule Trojan_Win64_CobaltStrike_FDS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 0c 24 03 c1 0f be 0c 24 c1 e1 10 33 c1 89 44 24 04 48 8b 44 24 20 48 ff c0 48 89 44 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}