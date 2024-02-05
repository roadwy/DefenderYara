
rule Trojan_Win64_CobaltStrike_C_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 b9 00 00 00 00 ff d0 49 89 90 01 01 48 8d 15 90 01 04 b9 06 00 00 00 b8 00 00 00 00 48 89 d7 f3 48 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}