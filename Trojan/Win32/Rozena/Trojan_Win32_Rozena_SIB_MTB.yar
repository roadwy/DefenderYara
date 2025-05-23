
rule Trojan_Win32_Rozena_SIB_MTB{
	meta:
		description = "Trojan:Win32/Rozena.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1b 00 06 00 00 "
		
	strings :
		$a_00_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_00_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_00_2 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_00_3 = {63 6d 64 2e 65 78 65 } //5 cmd.exe
		$a_03_4 = {8b 55 10 89 02 [0-0a] 90 18 8b 45 ?? 3b 45 0c 90 18 [0-10] 8b 45 90 1b 02 8d 14 85 00 00 00 00 8b 45 08 01 d0 8b 00 0f b6 84 05 ?? ?? ?? ?? 0f be c8 8b 45 10 8b 10 8b 45 10 8b 00 89 4c 24 0c 89 54 24 08 c7 44 24 04 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 83 45 90 1b 02 01 8b 45 90 1b 02 3b 45 0c } //10
		$a_03_5 = {58 31 c9 89 cb 6a 04 5a 43 ff 30 59 0f c9 31 d9 81 f9 ?? ?? ?? ?? 75 ?? 0f cb 31 c9 81 c1 ?? ?? ?? ?? 01 d0 31 18 e2 ?? 2d ?? ?? ?? ?? ff e0 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*5+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=27
 
}