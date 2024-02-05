
rule Trojan_BAT_Clipbanker_NCB_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 08 72 bd 07 00 70 28 90 01 02 00 0a 6f 90 01 02 00 06 6f 90 01 02 00 0a 25 07 6f 90 01 02 00 06 90 00 } //01 00 
		$a_01_1 = {52 00 6f 00 6f 00 62 00 65 00 74 00 43 00 72 00 61 00 73 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Clipbanker_NCB_MTB_2{
	meta:
		description = "Trojan:BAT/Clipbanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0c 13 00 fe 90 01 02 00 5c fe 90 01 02 00 58 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 58 fe 90 01 02 00 5a fe 90 01 02 00 58 fe 90 01 02 00 fe 90 01 02 00 16 40 90 01 03 00 fe 90 01 02 00 17 59 fe 90 01 02 00 90 00 } //01 00 
		$a_01_1 = {73 73 73 63 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}