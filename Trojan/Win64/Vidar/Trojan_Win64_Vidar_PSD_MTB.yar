
rule Trojan_Win64_Vidar_PSD_MTB{
	meta:
		description = "Trojan:Win64/Vidar.PSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {4c 89 f0 48 89 81 b8 ?? ?? ?? 48 8b 44 24 30 48 89 81 a8 ?? ?? ?? 48 8d 44 24 38 48 89 81 b0 ?? ?? ?? b8 01 ?? ?? ?? eb 02 31 c0 48 89 4c 24 20 88 44 24 1f 48 8b 15 b8 ?? ?? ?? 48 89 14 24 48 8d 91 78 ?? ?? ?? 48 89 54 24 08 e8 83 e5 02 00 45 0f 57 ff } //5
		$a_01_1 = {4d 61 70 4b 65 79 73 } //1 MapKeys
		$a_01_2 = {72 75 6e 74 69 6d 65 2e 70 65 72 73 69 73 74 65 6e 74 61 6c 6c 6f 63 } //1 runtime.persistentalloc
		$a_01_3 = {43 6f 72 65 44 75 6d 70 } //1 CoreDump
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}