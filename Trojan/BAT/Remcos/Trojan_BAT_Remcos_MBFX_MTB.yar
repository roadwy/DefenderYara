
rule Trojan_BAT_Remcos_MBFX_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 50 06 91 1c 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //01 00 
		$a_01_1 = {57 15 02 08 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 08 00 00 } //01 00 
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 35 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00  WindowsFormsApp50.Properties.Resources.resource
	condition:
		any of ($a_*)
 
}