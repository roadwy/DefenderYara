
rule VirTool_WinNT_Idicaf_A{
	meta:
		description = "VirTool:WinNT/Idicaf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 00 66 c7 45 ?? 68 00 66 c7 45 ?? 79 00 66 c7 45 ?? 73 00 } //2
		$a_03_1 = {68 42 52 69 6e 56 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 31 8d 45 fc 50 56 57 ff 75 08 ff 15 } //2
		$a_03_2 = {eb 37 60 8b c0 61 e8 ?? ?? ff ff a1 ?? ?? ?? ?? 8b 40 01 8b 0d ?? ?? ?? ?? 8b 55 f8 89 0c 82 83 25 ?? ?? ?? ?? 00 fb } //1
		$a_01_3 = {42 72 65 61 6b 49 6e 2e 70 64 62 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}