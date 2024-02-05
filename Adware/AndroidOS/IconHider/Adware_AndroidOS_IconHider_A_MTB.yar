
rule Adware_AndroidOS_IconHider_A_MTB{
	meta:
		description = "Adware:AndroidOS/IconHider.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 70 69 2e 31 6f 63 65 61 6e 73 2e 63 6f 6d } //01 00 
		$a_01_1 = {67 65 74 43 6c 69 63 6b 53 70 } //01 00 
		$a_01_2 = {63 6c 69 63 6b 44 65 6c 61 79 54 69 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}