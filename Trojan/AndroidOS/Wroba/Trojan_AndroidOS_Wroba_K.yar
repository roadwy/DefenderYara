
rule Trojan_AndroidOS_Wroba_K{
	meta:
		description = "Trojan:AndroidOS/Wroba.K,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6c 69 63 6b 2d 70 68 6f 6e 65 2d 72 65 6a 65 63 74 } //02 00  click-phone-reject
		$a_01_1 = {74 6d 70 4f 75 74 4e 75 6d 62 65 72 3d } //00 00  tmpOutNumber=
	condition:
		any of ($a_*)
 
}