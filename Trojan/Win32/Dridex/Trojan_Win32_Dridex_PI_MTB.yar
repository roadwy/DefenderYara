
rule Trojan_Win32_Dridex_PI_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {fe 51 4e 62 0b fd c4 90 c3 35 a5 6b ce cf 49 42 2d 8a 18 9b e6 fe 67 d8 d3 61 d0 34 c9 8d be 4f 1e 84 6d e1 8a fe c4 a4 c3 16 86 9e 01 cf 49 41 } //01 00 
		$a_81_1 = {48 42 49 54 4d 41 50 5f 55 73 65 72 53 69 7a 65 } //01 00  HBITMAP_UserSize
		$a_81_2 = {50 6f 6c 79 6c 69 6e 65 54 6f } //01 00  PolylineTo
		$a_81_3 = {46 69 6e 64 43 6c 6f 73 65 55 72 6c 43 61 63 68 65 } //01 00  FindCloseUrlCache
		$a_81_4 = {53 77 69 74 63 68 54 6f 54 68 69 73 57 69 6e 64 6f 77 } //01 00  SwitchToThisWindow
		$a_81_5 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } //01 00  LoadKeyboardLayoutA
		$a_81_6 = {4f 70 65 6e 53 65 6d 61 70 68 6f 72 65 57 } //00 00  OpenSemaphoreW
	condition:
		any of ($a_*)
 
}