
rule Trojan_Win32_RedLineStealer_MC_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 95 9c fd ff ff 83 c2 01 89 95 9c fd ff ff 83 bd 9c fd ff ff 0c 73 90 01 01 8b 85 9c fd ff ff 0f b6 4c 05 d0 81 c1 b5 00 00 00 8b 95 9c fd ff ff 88 4c 15 d0 eb 90 01 01 c6 45 cd 00 0f b6 45 d1 85 c0 74 90 00 } //01 00 
		$a_01_1 = {55 6e 6c 6f 63 6b 46 69 6c 65 45 78 } //01 00  UnlockFileEx
		$a_01_2 = {47 65 74 43 50 49 6e 66 6f 45 78 57 } //01 00  GetCPInfoExW
		$a_01_3 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 41 } //01 00  GetDiskFreeSpaceA
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_MC_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 1d 44 f1 47 00 8b 4d f4 8b c6 d3 e8 8b 4d e4 c7 05 4c 23 48 00 2e ce 50 91 89 45 f0 8d 45 f0 e8 96 fe ff ff 8b 45 fc 03 c6 50 8b 45 f8 e8 7a fe ff ff 8b 4d f0 33 c8 89 45 f8 2b f9 25 bb 52 c0 5d 8b c7 8d 4d f8 e8 58 fe ff ff 8b 4d d8 8b c7 c1 e8 05 89 45 f0 8d 45 f0 e8 5c fe ff ff 8b 45 fc 8b 4d dc 03 c7 50 8b 45 f8 03 c1 e8 3b fe ff ff 8b 4d f0 89 45 f8 8d 45 f8 e8 2a fe ff ff 2b 75 f8 89 1d 28 e3 47 00 8b 45 e8 29 45 fc ff 4d ec 0f 85 } //01 00 
		$a_03_1 = {89 55 fc b8 90 01 04 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}