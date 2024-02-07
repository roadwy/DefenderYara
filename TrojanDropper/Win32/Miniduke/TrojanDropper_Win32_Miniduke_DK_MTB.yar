
rule TrojanDropper_Win32_Miniduke_DK_MTB{
	meta:
		description = "TrojanDropper:Win32/Miniduke.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 55 08 c6 42 03 3d 0f b6 45 fb 8b 4d 08 8b 55 f4 8a 04 02 88 41 02 eb 0e 8b 4d 08 c6 41 02 3d 8b 55 08 c6 42 03 3d 0f b6 45 f3 8b 4d 08 8b 55 f4 8a 04 02 88 41 01 e9 } //02 00 
		$a_01_1 = {25 73 25 63 25 63 25 64 72 25 63 74 2e 65 78 65 } //02 00  %s%c%c%dr%ct.exe
		$a_01_2 = {77 69 6e 61 72 63 2e 65 78 65 } //00 00  winarc.exe
	condition:
		any of ($a_*)
 
}