
rule Trojan_Win64_Bumblebee_QMV_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.QMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c1 41 8b d0 41 89 81 90 01 04 41 8b 81 90 01 04 35 90 01 04 c1 ea 90 01 01 41 29 81 90 01 04 49 63 49 90 01 01 49 8b 81 90 01 04 88 14 01 41 8b d0 41 ff 41 90 01 01 41 8b 41 90 01 01 41 8b 89 90 01 04 81 e9 90 01 04 c1 ea 90 01 01 0f af c1 41 89 41 90 01 01 41 8b 01 ff c8 90 00 } //01 00 
		$a_01_1 = {55 7a 45 50 78 } //00 00  UzEPx
	condition:
		any of ($a_*)
 
}