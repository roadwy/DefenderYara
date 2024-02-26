
rule Trojan_Win64_Rozena_NR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {e8 5d 2c ff ff 48 89 6b 90 01 01 48 8b 2d 52 40 01 00 41 bb 90 01 04 4c 89 23 4c 90 00 } //03 00 
		$a_03_1 = {45 31 c0 4c 89 e1 48 8b 05 f9 41 01 00 66 44 89 87 90 01 04 48 c7 87 e8 00 00 00 90 01 04 48 8d 50 18 48 83 c0 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}