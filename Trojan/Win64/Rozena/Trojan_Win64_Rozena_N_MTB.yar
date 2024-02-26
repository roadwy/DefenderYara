
rule Trojan_Win64_Rozena_N_MTB{
	meta:
		description = "Trojan:Win64/Rozena.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {48 8b 2d b0 32 0e 00 31 ff 65 48 8b 04 25 90 01 04 48 8b 70 08 90 00 } //03 00 
		$a_03_1 = {48 8b 05 e3 2f 0e 00 ff d0 bb 90 01 04 48 8d 45 d0 48 89 c1 e8 d0 f0 09 00 89 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}