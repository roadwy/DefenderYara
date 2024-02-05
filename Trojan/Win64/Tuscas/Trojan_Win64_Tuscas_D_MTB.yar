
rule Trojan_Win64_Tuscas_D_MTB{
	meta:
		description = "Trojan:Win64/Tuscas.D!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b d0 c1 ea 1c 80 e2 0f 0f b6 ca 8d 41 30 66 83 c1 57 80 fa 39 66 0f 46 c8 41 c1 e0 04 66 41 89 09 4d 8d 49 02 49 ff ca 75 } //01 00 
		$a_01_1 = {42 8d 04 12 0f b6 c8 41 8b 00 d3 c8 41 33 c3 2b c2 41 89 00 4d 8d 40 04 ff ca 75 e4 } //00 00 
	condition:
		any of ($a_*)
 
}