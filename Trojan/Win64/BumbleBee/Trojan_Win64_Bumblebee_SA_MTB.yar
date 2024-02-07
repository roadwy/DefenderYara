
rule Trojan_Win64_Bumblebee_SA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 43 28 48 8b 8b 90 01 04 48 2d 90 01 04 48 89 83 90 01 04 48 c7 c0 90 01 04 48 2b 83 90 01 04 48 01 41 90 01 01 48 8b 8b 90 01 04 48 8b 81 90 01 04 48 31 43 90 01 01 4a 8d 04 2a 48 90 01 06 48 90 01 04 48 09 ab 90 01 04 e9 90 00 } //01 00 
		$a_00_1 = {45 73 73 55 72 33 36 35 66 4f 4c 31 } //00 00  EssUr365fOL1
	condition:
		any of ($a_*)
 
}