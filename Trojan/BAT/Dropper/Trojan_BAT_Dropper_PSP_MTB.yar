
rule Trojan_BAT_Dropper_PSP_MTB{
	meta:
		description = "Trojan:BAT/Dropper.PSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 8c 06 00 70 a2 28 36 90 01 03 6f 1f 90 01 03 11 0f 16 6f 38 90 01 03 11 0f 17 6f 37 90 01 03 11 0f 28 3a 90 01 03 20 e8 03 00 00 6f 3c 90 01 03 26 72 3a 06 00 70 73 3b 90 01 03 13 0f 11 0f 1b 8d 21 00 00 01 25 90 00 } //01 00 
		$a_01_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //01 00  schtasks
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}