
rule Trojan_AndroidOS_DropperAgent_O{
	meta:
		description = "Trojan:AndroidOS/DropperAgent.O,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 65 6e 64 6f 75 41 63 74 69 76 69 74 79 } //02 00  FendouActivity
		$a_01_1 = {61 70 69 2f 46 65 6e 64 6f 75 63 } //02 00  api/Fendouc
		$a_01_2 = {46 65 6e 64 6f 75 49 4d 61 6e 61 67 65 72 } //00 00  FendouIManager
	condition:
		any of ($a_*)
 
}