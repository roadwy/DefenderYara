
rule Trojan_AndroidOS_Fakeapp_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 65 62 56 69 65 77 47 69 72 6c 73 } //01 00 
		$a_00_1 = {26 70 72 6f 64 75 63 74 53 4c 3d } //01 00 
		$a_00_2 = {61 70 69 26 74 72 61 63 6b 69 6e 67 3d } //01 00 
		$a_01_3 = {77 65 62 56 69 65 77 54 65 72 6d 73 } //01 00 
		$a_01_4 = {61 70 70 5f 64 62 3d 61 70 6b 73 5f 64 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}