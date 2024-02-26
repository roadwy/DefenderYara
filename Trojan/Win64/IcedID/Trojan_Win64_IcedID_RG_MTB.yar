
rule Trojan_Win64_IcedID_RG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 7a 7a 73 70 64 64 6c 61 69 67 71 61 6e 2e 64 6c 6c } //01 00  qzzspddlaigqan.dll
		$a_01_1 = {61 6d 6a 75 76 64 6e 69 67 72 6d 75 66 77 6a 77 67 00 61 71 62 73 74 69 76 69 67 66 77 } //01 00 
		$a_01_2 = {66 62 6f 77 63 67 64 6f 64 77 6b 73 62 78 6a 61 } //00 00  fbowcgdodwksbxja
	condition:
		any of ($a_*)
 
}