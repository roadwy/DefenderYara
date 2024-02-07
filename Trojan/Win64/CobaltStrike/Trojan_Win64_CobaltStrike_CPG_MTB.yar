
rule Trojan_Win64_CobaltStrike_CPG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {43 8d 0c 08 0f be c9 6b d1 90 01 01 80 90 01 02 41 30 10 49 ff c0 4b 8d 0c 01 48 81 90 01 05 72 90 00 } //01 00 
		$a_01_1 = {43 50 6c 41 70 70 6c 65 74 } //00 00  CPlApplet
	condition:
		any of ($a_*)
 
}