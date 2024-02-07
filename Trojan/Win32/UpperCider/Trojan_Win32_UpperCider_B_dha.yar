
rule Trojan_Win32_UpperCider_B_dha{
	meta:
		description = "Trojan:Win32/UpperCider.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {78 6c 41 75 74 6f 4f 70 65 6e } //03 00  xlAutoOpen
		$a_81_1 = {52 65 67 69 73 74 65 72 58 4c 4c 2e 64 6c 6c } //05 00  RegisterXLL.dll
		$a_03_2 = {01 00 00 0f b6 b8 01 01 00 00 0f b6 f2 0f b6 1c 06 02 1c 07 fe c2 0f b6 f3 0f b6 1c 06 8b 75 90 01 01 32 1c 0e 88 90 90 00 01 00 00 0f b6 fa 0f b6 14 07 00 90 90 01 01 00 00 0f b6 b0 01 01 00 00 90 00 } //05 00 
		$a_03_3 = {8a 14 07 88 59 01 0f b6 1c 06 88 1c 07 88 14 06 8a 90 90 00 01 00 00 0f b6 b8 01 01 00 00 0f b6 f2 0f b6 1c 06 02 1c 07 83 c1 03 0f b6 f3 0f b6 1c 06 8b 75 90 01 01 32 5c 0e fd ff 4d fc 88 59 ff 0f 85 90 00 } //0a 00 
		$a_03_4 = {6a 00 68 14 04 00 03 6a 00 6a 00 6a 00 8d 90 02 06 6a 00 ff 15 90 01 04 85 c0 74 90 01 05 6a 40 68 00 30 00 00 57 6a 00 52 ff 15 90 02 1b 6a 00 57 50 56 51 ff 15 90 01 04 85 c0 90 02 08 6a 00 6a 00 6a 00 56 6a 00 6a 00 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}