
rule Trojan_BAT_Injuke_SPD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {02 72 01 00 00 70 28 90 01 03 06 0a 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 0b 02 07 28 90 01 03 06 0c dd 06 00 00 00 90 00 } //01 00 
		$a_01_1 = {58 71 73 79 67 64 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}