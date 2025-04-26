
rule Backdoor_Win32_Refpron_R{
	meta:
		description = "Backdoor:Win32/Refpron.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {b9 30 00 00 00 6a 00 6a 00 49 75 f9 53 33 c0 55 68 ?? 75 01 00 64 ff 30 64 89 20 68 ?? ?? ?? 40 6a 00 8d 55 fc b8 ?? 75 01 00 e8 ?? d7 ff ff 8b 45 fc e8 ?? c7 ff ff 8b 15 40 92 01 00 89 02 68 ?? ?? ?? 40 6a 00 8d 55 fc b8 ?? 75 01 00 e8 ?? d7 ff ff 8b 45 fc e8 ?? c7 ff ff 8b 15 5c 91 01 00 89 02 68 ?? ?? ?? 40 6a 00 } //1
		$a_02_1 = {0f b7 45 f0 c1 e8 08 89 45 e4 83 6d ec ?? 8b 45 f4 e8 ?? e7 ff ff 0f b7 55 f2 8a 4d e8 32 4d e4 88 4c 10 ff } //1
		$a_00_2 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_00_3 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2c 39 39 20 42 6f 72 6c 61 6e 64 } //1 Portions Copyright (c) 1983,99 Borland
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}