
rule VirTool_Win32_Obfuscator_AX{
	meta:
		description = "VirTool:Win32/Obfuscator.AX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 69 44 20 54 65 61 6d 2e 50 72 6f 74 65 63 74 69 6f 6e 49 44 } //-100 PiD Team.ProtectionID
		$a_03_1 = {81 fe ff ff 00 00 7c ed 64 a1 18 00 00 00 8b 40 34 88 45 ff 80 7d ff 64 8b 45 f4 73 ?? 8b ?? 3c } //2
		$a_03_2 = {f6 eb 8d 0c 3a 30 01 8a 01 02 45 ?? 88 01 8b 5d ?? 8a 5b 08 32 d8 f6 d3 42 88 19 3b 56 04 72 dc 90 09 04 00 8a c2 b3 } //2
		$a_03_3 = {eb 1f 8b 06 3d 00 00 00 80 72 05 0f b7 c0 eb 07 8b 4d ?? 8d 44 08 02 50 53 ff 55 ?? 89 06 83 c6 04 83 3e 00 75 dc } //1
		$a_01_4 = {55 8b ec 87 e5 5d e9 } //1
	condition:
		((#a_01_0  & 1)*-100+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}