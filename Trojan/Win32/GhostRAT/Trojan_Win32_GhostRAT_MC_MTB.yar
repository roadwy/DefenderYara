
rule Trojan_Win32_GhostRAT_MC_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 f8 8b 0d ?? ?? ?? ?? 8b 55 f8 3b 91 fc 05 00 00 73 ?? 8b 45 f4 33 c9 8a 08 8b 55 fc 81 e2 ff 00 00 00 33 ca 8b 45 f4 88 08 8b 4d f4 83 c1 01 89 4d f4 eb } //1
		$a_01_1 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //1 SuspendThread
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}