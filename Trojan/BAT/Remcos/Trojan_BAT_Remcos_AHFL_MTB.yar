
rule Trojan_BAT_Remcos_AHFL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 06 11 08 9a 1f 10 28 90 01 03 0a 8c 59 00 00 01 6f 90 01 03 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 90 00 } //01 00 
		$a_01_1 = {47 00 55 00 49 00 5f 00 44 00 65 00 6d 00 6f 00 31 00 } //00 00  GUI_Demo1
	condition:
		any of ($a_*)
 
}