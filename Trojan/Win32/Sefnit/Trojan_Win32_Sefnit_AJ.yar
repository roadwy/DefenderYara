
rule Trojan_Win32_Sefnit_AJ{
	meta:
		description = "Trojan:Win32/Sefnit.AJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0d 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff b0 40 07 00 00 90 02 13 ff b0 3c 07 00 00 90 02 13 90 03 02 01 ff 15 e8 90 00 } //01 00 
		$a_03_1 = {ff b2 40 07 00 00 90 02 0f ff b2 3c 07 00 00 90 02 10 90 03 02 01 ff 15 e8 90 00 } //01 00 
		$a_03_2 = {ff b1 40 07 00 00 90 02 0f ff b1 3c 07 00 00 90 02 0e 90 03 02 01 ff 15 e8 90 00 } //01 00 
		$a_01_3 = {89 86 40 07 00 00 89 86 3c 07 00 00 } //01 00 
		$a_01_4 = {89 9e 3c 07 00 00 89 9e 44 07 00 00 } //01 00 
		$a_01_5 = {89 86 3c 07 00 00 89 86 44 07 00 00 } //01 00 
		$a_01_6 = {89 96 3c 07 00 00 89 96 44 07 00 00 } //01 00 
		$a_03_7 = {c0 ff 7f c9 c2 90 09 02 00 2d 90 00 } //01 00 
		$a_03_8 = {0f be c3 69 c0 90 01 03 00 05 90 00 } //01 00 
		$a_03_9 = {80 7b 06 3a 0f 85 90 01 04 80 7b 07 2f 90 00 } //01 00 
		$a_03_10 = {80 78 06 3a 0f 85 90 01 04 80 78 07 2f 90 00 } //01 00 
		$a_03_11 = {50 8b c6 69 c0 90 01 04 05 90 01 04 50 90 00 } //9c ff 
		$a_00_12 = {46 6c 61 73 68 50 6c 61 79 65 72 43 6f 6e 74 72 6f 6c 5f 25 73 5f 25 64 } //00 00  FlashPlayerControl_%s_%d
	condition:
		any of ($a_*)
 
}