
rule Trojan_Win32_Rozena_SIB_MTB{
	meta:
		description = "Trojan:Win32/Rozena.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1b 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_00_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_00_2 = {43 72 65 61 74 65 54 68 72 65 61 64 } //05 00  CreateThread
		$a_00_3 = {63 6d 64 2e 65 78 65 } //0a 00  cmd.exe
		$a_03_4 = {8b 55 10 89 02 90 02 0a 90 18 8b 45 90 01 01 3b 45 0c 90 18 90 02 10 8b 45 90 1b 02 8d 14 85 00 00 00 00 8b 45 08 01 d0 8b 00 0f b6 84 05 90 01 04 0f be c8 8b 45 10 8b 10 8b 45 10 8b 00 89 4c 24 0c 89 54 24 08 c7 44 24 04 90 01 04 89 04 24 e8 90 01 04 83 45 90 1b 02 01 8b 45 90 1b 02 3b 45 0c 90 00 } //0a 00 
		$a_03_5 = {58 31 c9 89 cb 6a 04 5a 43 ff 30 59 0f c9 31 d9 81 f9 90 01 04 75 90 01 01 0f cb 31 c9 81 c1 90 01 04 01 d0 31 18 e2 90 01 01 2d 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}