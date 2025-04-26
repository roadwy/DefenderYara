
rule TrojanClicker_Win32_Small_JE{
	meta:
		description = "TrojanClicker:Win32/Small.JE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d 08 00 74 2f 83 65 fc 00 8d 45 fc 50 b8 00 01 00 00 2b c6 50 8b 45 0c 03 c6 50 ff 75 08 } //1
		$a_01_1 = {85 c0 8b 4d fc 75 04 33 c9 85 c0 0f 95 c0 eb 02 32 c0 84 c0 74 08 85 c9 74 04 03 f1 eb bd 8b c6 5e c9 } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 66 65 73 74 69 76 61 6c 32 33 32 33 34 2e 63 6f 6d 2f 66 6c 61 73 68 2e 70 68 70 3f 6d 6f 64 65 3d 31 } //1 http://festival23234.com/flash.php?mode=1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}