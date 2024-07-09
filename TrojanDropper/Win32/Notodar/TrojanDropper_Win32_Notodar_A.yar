
rule TrojanDropper_Win32_Notodar_A{
	meta:
		description = "TrojanDropper:Win32/Notodar.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 25 00 73 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 } //1 %s\%s\rundll32.exe "%s" update
		$a_03_1 = {8b 4d 7c 83 c4 14 6a 0a 6a 1e 58 8d 7d dc e8 ?? ?? ?? ?? 53 8b c7 50 68 02 00 00 80 e8 ?? ?? ?? ?? 8b f8 3b fe 75 11 53 8d 45 dc 50 68 01 00 00 80 e8 } //1
		$a_01_2 = {53 56 57 89 45 dc bb e5 55 9a 15 bf b5 3b 12 1f be 33 13 49 05 6a 01 83 } //1
		$a_01_3 = {68 00 00 00 08 89 45 f0 6a 40 8d 45 f0 50 8d 45 d8 50 68 1f 00 0f 00 8d 45 f8 50 c7 45 d8 18 00 00 00 89 7d dc c7 45 e4 02 00 00 00 89 7d e0 89 7d e8 89 7d ec 89 7d f4 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}