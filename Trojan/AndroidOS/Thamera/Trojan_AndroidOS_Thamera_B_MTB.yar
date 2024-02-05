
rule Trojan_AndroidOS_Thamera_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 2e 36 73 72 76 66 63 6d } //01 00 
		$a_01_1 = {70 69 64 61 72 61 73 74 2e 72 75 } //01 00 
		$a_00_2 = {63 6f 6d 2e 73 65 74 74 69 6e 67 61 70 70 2e 61 70 70 } //01 00 
		$a_01_3 = {2f 73 6d 73 61 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}