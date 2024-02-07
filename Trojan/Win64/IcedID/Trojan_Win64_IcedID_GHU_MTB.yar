
rule Trojan_Win64_IcedID_GHU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 67 64 34 32 61 } //01 00  Fgd42a
		$a_01_1 = {4a 4f 46 4c 54 35 4e } //01 00  JOFLT5N
		$a_01_2 = {51 62 56 70 6d 61 32 30 38 63 73 4a } //01 00  QbVpma208csJ
		$a_01_3 = {53 74 61 72 74 4d 4e 45 } //01 00  StartMNE
		$a_01_4 = {77 67 79 75 66 6f 79 } //00 00  wgyufoy
	condition:
		any of ($a_*)
 
}