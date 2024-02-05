
rule Trojan_Win32_Stealer_CH_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 a8 0e 4e 00 8a 84 07 90 02 04 8b 0d 90 02 04 88 04 0f 81 3d 90 02 08 75 0b 8d 44 24 1c 50 ff 15 90 02 04 47 3b 3d 90 02 04 72 cb 90 00 } //01 00 
		$a_03_1 = {83 ff 26 75 05 e8 90 02 04 47 81 ff b7 c4 3d 00 7c ed 90 00 } //01 00 
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}