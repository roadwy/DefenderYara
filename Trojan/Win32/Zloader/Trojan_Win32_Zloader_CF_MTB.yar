
rule Trojan_Win32_Zloader_CF_MTB{
	meta:
		description = "Trojan:Win32/Zloader.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 31 2e 64 6c 6c } //01 00  Project1.dll
		$a_01_1 = {77 68 6f 61 6d 69 2e 65 78 65 } //01 00  whoami.exe
		$a_01_2 = {79 79 68 68 6a 66 } //01 00  yyhhjf
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {6a 67 66 67 66 63 63 64 73 68 67 6a 68 67 68 6a } //01 00  jgfgfccdshgjhghj
		$a_01_6 = {67 67 64 72 65 72 65 72 65 72 64 66 67 68 66 68 67 66 68 67 } //01 00  ggdrerererdfghfhgfhg
		$a_01_7 = {66 66 63 64 65 65 65 67 } //00 00  ffcdeeeg
	condition:
		any of ($a_*)
 
}