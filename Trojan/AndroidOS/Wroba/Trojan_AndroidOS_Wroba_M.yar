
rule Trojan_AndroidOS_Wroba_M{
	meta:
		description = "Trojan:AndroidOS/Wroba.M,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6e 50 72 6f 63 65 73 73 44 69 65 } //01 00  onProcessDie
		$a_01_1 = {3a 57 6f 72 6b 63 63 6f } //00 00  :Workcco
	condition:
		any of ($a_*)
 
}