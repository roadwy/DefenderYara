
rule Trojan_Win32_Rootkit_R{
	meta:
		description = "Trojan:Win32/Rootkit.R,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {5a 77 4c 6f 61 64 44 72 69 76 65 72 } //1 ZwLoadDriver
		$a_00_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_2 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 33 00 32 00 5f 00 72 00 6b 00 74 00 2e 00 73 00 79 00 73 00 } //1 \??\C:\WINDOWS\SYSTEM32\win32_rkt.sys
		$a_00_3 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 4d 00 75 00 73 00 69 00 63 00 } //1 \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\DMusic
		$a_00_4 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 44 00 4d 00 75 00 73 00 69 00 63 00 2e 00 73 00 79 00 73 00 } //1 \drivers\DMusic.sys
		$a_00_5 = {67 00 5f 00 72 00 6b 00 74 00 } //1 g_rkt
		$a_00_6 = {8d 54 36 1e 6a 00 89 44 24 24 66 89 4c 24 20 66 89 54 24 22 6a 60 6a 02 6a 00 6a 00 6a 00 8d 44 24 54 50 8d 4c 24 40 51 68 80 00 10 40 8d 54 24 38 52 ff d3 } //1
		$a_02_7 = {8b c8 03 0d ?? ?? 01 00 83 ca ff e8 ?? ?? ff ff 3d 5b f0 6a c7 74 15 3d 45 30 34 01 74 0e 3d 45 d0 fa 58 74 07 5d ff 25 14 09 01 00 e8 ?? ?? ff ff b8 34 00 00 c0 5d c2 2c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}