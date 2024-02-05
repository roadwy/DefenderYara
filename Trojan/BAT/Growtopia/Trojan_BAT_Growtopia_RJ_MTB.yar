
rule Trojan_BAT_Growtopia_RJ_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 14 fe 03 0c 08 2c 31 00 00 07 0d 16 13 04 2b 1c 09 11 04 9a 13 05 00 06 11 05 28 90 01 04 28 90 01 04 0a 00 11 04 17 58 13 04 11 04 09 8e 69 32 dd 90 00 } //01 00 
		$a_01_1 = {47 00 72 00 6f 00 77 00 74 00 6f 00 70 00 69 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}