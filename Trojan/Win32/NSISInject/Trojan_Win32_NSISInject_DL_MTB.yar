
rule Trojan_Win32_NSISInject_DL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 c7 45 f0 00 a3 e1 11 89 45 ec 8b 45 ec 89 45 e8 83 7d f0 00 0f 84 ?? ?? ?? ?? 8b 45 e8 c6 00 00 8b 45 e8 83 c0 01 89 45 e8 8b 45 f0 83 c0 ff 89 45 f0 e9 } //1
		$a_81_1 = {4c 4c 44 20 50 44 42 2e } //1 LLD PDB.
		$a_03_2 = {78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 4c 6f 63 74 5c [0-20] 5c 4c 6f 61 64 65 72 5c [0-0f] 5c 52 65 6c 65 61 73 65 5c [0-0f] 2e 70 64 62 } //1
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_DL_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 45 dc c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 4d d8 ff 55 dc } //5
		$a_03_1 = {89 f9 29 f1 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 90 09 13 00 88 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 3d } //1
		$a_03_2 = {89 f9 31 f1 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 90 09 13 00 88 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 3d } //1
		$a_03_3 = {89 f9 01 f1 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? c1 fe 05 0f b6 3d ?? ?? ?? ?? c1 e7 03 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 90 09 13 00 88 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 3d } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}