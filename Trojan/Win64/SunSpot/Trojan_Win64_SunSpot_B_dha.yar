
rule Trojan_Win64_SunSpot_B_dha{
	meta:
		description = "Trojan:Win64/SunSpot.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7b 31 32 64 36 31 61 34 31 2d 34 62 37 34 2d 37 90 01 01 31 30 2d 61 34 64 38 2d 33 30 32 38 64 32 66 35 36 33 39 35 7d 90 00 } //01 00 
		$a_03_1 = {7b 35 36 33 33 31 65 34 64 2d 37 36 61 33 2d 30 33 39 30 2d 61 37 90 01 01 65 2d 35 36 37 61 64 66 35 38 33 36 62 37 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}