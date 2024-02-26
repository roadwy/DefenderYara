
rule Trojan_Win64_Rozena_NA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {48 89 44 f2 10 48 8d 3c f2 83 3d a2 4d 1b 00 90 01 01 75 09 4c 89 04 f2 90 00 } //03 00 
		$a_03_1 = {75 24 48 8b 44 24 90 01 01 48 89 81 08 01 01 00 48 8b 05 4d d0 16 00 48 89 81 f8 00 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}