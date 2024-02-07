
rule Trojan_Win32_SpyBot_BZ_MTB{
	meta:
		description = "Trojan:Win32/SpyBot.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 67 73 2f 68 65 61 64 65 72 2e 67 69 66 22 20 61 6c 74 3d 22 53 70 79 42 6f 74 22 3e } //01 00  bgs/header.gif" alt="SpyBot">
		$a_00_1 = {73 70 79 62 6f 74 2f 63 73 73 2f 73 63 72 65 65 6e 2e 63 73 73 22 2f 3e } //01 00  spybot/css/screen.css"/>
		$a_00_2 = {53 00 70 00 79 00 62 00 6f 00 74 00 20 00 2d 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 26 00 20 00 44 00 65 00 73 00 74 00 72 00 6f 00 79 00 } //01 00  Spybot - Search & Destroy
		$a_00_3 = {53 00 44 00 46 00 53 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //01 00  SDFSSvc.exe
		$a_03_4 = {83 c4 08 b8 90 01 04 ff e0 8b e5 5d 90 00 } //01 00 
		$a_00_5 = {65 69 6f 72 72 79 75 62 34 6a 35 39 79 75 62 39 33 35 6e 79 39 76 33 34 38 75 72 38 39 74 76 75 33 34 30 39 72 38 76 74 75 34 39 38 72 39 38 } //01 00  eiorryub4j59yub935ny9v348ur89tvu3409r8vtu498r98
		$a_00_6 = {6d 61 64 43 6f 64 65 48 6f 6f 6b } //00 00  madCodeHook
	condition:
		any of ($a_*)
 
}