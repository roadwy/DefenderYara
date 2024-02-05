
rule Trojan_Win32_Zbot_AB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {c7 45 fc d3 9e 08 00 8b 55 0c 03 55 f4 0f b6 02 89 45 f8 c7 45 fc d3 9e 08 00 8b 4d 08 03 4d f4 8a 55 f8 88 11 } //03 00 
		$a_80_1 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //Toolhelp32ReadProcessMemory  03 00 
		$a_80_2 = {47 6b 7a 43 41 6f 65 78 6d 41 63 58 43 67 30 68 4c } //GkzCAoexmAcXCg0hL  00 00 
	condition:
		any of ($a_*)
 
}