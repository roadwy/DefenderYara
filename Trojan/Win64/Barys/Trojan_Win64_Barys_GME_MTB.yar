
rule Trojan_Win64_Barys_GME_MTB{
	meta:
		description = "Trojan:Win64/Barys.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b1 9f 33 7e 9c 87 18 89 80 90 01 04 0a 82 90 00 } //01 00 
		$a_01_1 = {37 65 37 66 65 6b 61 51 } //01 00  7e7fekaQ
		$a_01_2 = {72 46 35 75 58 52 78 } //00 00  rF5uXRx
	condition:
		any of ($a_*)
 
}