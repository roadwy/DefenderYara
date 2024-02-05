
rule Trojan_Win64_CobaltStrike_CRDD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 00 00 08 00 33 c9 41 b9 40 00 00 00 41 b8 00 10 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}