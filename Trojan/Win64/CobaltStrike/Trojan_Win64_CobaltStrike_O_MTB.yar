
rule Trojan_Win64_CobaltStrike_O_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {44 8b f8 85 c0 78 90 01 01 48 83 c6 06 48 ff 90 00 } //02 00 
		$a_01_1 = {49 8b ce 4c 8b c6 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}