
rule Trojan_Win64_KillAV_RPY_MTB{
	meta:
		description = "Trojan:Win64/KillAV.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 c9 10 2b c1 35 74 23 30 02 8b c8 48 c1 e1 08 48 c1 e8 18 48 0b c1 } //00 00 
	condition:
		any of ($a_*)
 
}