
rule Trojan_Win32_Zbot_ZR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 7d d8 8b 55 e0 23 fa 89 7d e0 8b 45 c8 8b 55 e0 33 c2 89 45 e0 8b 35 00 00 43 00 f7 d6 46 89 35 90 01 04 8b 05 90 01 04 8b 15 90 01 04 2b c2 89 15 93 37 43 00 e9 80 00 00 00 90 00 } //0a 00 
		$a_02_1 = {8b 3d cf 87 44 00 f7 df 81 c7 90 01 04 89 3d 90 01 04 8b 15 90 01 04 81 ea 90 01 04 83 c2 68 f7 d2 89 15 90 01 04 8b 1d 90 01 04 8b 15 90 01 04 23 d3 89 1d 90 01 04 8b 05 90 01 04 8b 0d 90 01 04 33 c1 89 0d ef 87 44 00 8b 35 97 37 43 00 81 f6 e1 0a 38 85 89 35 3c 00 43 00 c9 c2 10 00 90 00 } //01 00 
		$a_80_2 = {42 72 69 64 65 2e 65 78 65 } //Bride.exe  01 00 
		$a_01_3 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00  LoadResource
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {57 69 6e 45 78 65 63 } //00 00  WinExec
	condition:
		any of ($a_*)
 
}