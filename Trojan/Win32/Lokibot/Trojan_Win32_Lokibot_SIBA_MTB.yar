
rule Trojan_Win32_Lokibot_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 00 75 00 72 00 65 00 78 00 } //1 Murex
		$a_03_1 = {66 0f ec e5 0f [0-5a] 81 34 1a ?? ?? ?? ?? [0-30] 43 [0-35] 43 [0-2a] 43 [0-40] 43 [0-3a] 81 fb 8c 0d 01 00 [0-05] 90 18 0f 85 ?? ?? ?? ?? 90 08 bd 01 ff d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Lokibot_SIBA_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 75 72 6f 67 61 79 65 6e 65 73 6f 2d 6b 75 63 6f 6e 75 6e 65 67 6f 6e 75 5c 79 61 63 69 62 61 76 2d 62 65 74 65 63 69 62 75 74 65 6d 65 6b 5c 67 69 64 69 6a 69 2e 70 64 62 } //1 curogayeneso-kuconunegonu\yacibav-betecibutemek\gidiji.pdb
		$a_03_1 = {8b c7 c1 e0 04 89 45 ?? [0-40] 8b 45 ?? 8d 0c 38 8b 45 ?? c1 e8 ?? 89 45 ?? 31 4d 90 1b 00 8b 45 90 1b 05 8b 4d ?? 03 c1 33 45 90 1b 00 [0-20] 89 45 90 1b 05 75 ?? [0-10] 8b 45 90 1b 05 29 45 ?? [0-20] 8b 75 90 1b 0f [0-0a] 8b c6 d3 e0 8b 4d 90 1b 02 8b d6 c1 ea ?? 03 45 ?? 03 55 ?? 03 ce 33 c1 33 c2 2b f8 89 55 90 1b 05 [0-0a] 89 7d 90 1b 03 8b 45 ?? 29 45 90 1b 02 ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 08 8b 4d 90 1b 0f 89 38 [0-0a] 89 48 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}