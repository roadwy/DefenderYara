
rule VirTool_Win32_Obfuscator_VE{
	meta:
		description = "VirTool:Win32/Obfuscator.VE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 cf 03 ce 3b ca 8b 4d f8 8a 09 88 4d ff ([0-20] 0f b6 4d ff 9|0 17 03 0c 11 16 [0-20] 90 18 [0-20]) 0f b6 4d ff [0-20] 90 18 [0-20] 90 18 [0-20] 0f b6 4d ff [0-20] 90 18 [0-20] 90 18 [0-20] 90 18 [0-20] 0f b6 4d ff 90 03 05 0a [0-20] 83 f1 [0-20] 90 18 [0-20] 83 f1 [0-20] 81 c1 ?? 00 00 00 } //1
		$a_02_1 = {8b 45 dc 03 45 f8 [0-20] 8d 34 08 [0-20] 8a c1 [0-20] 02 45 f8 [0-20] 02 4d f8 [0-20] 04 04 ([0-20] fe c1 [|0-20] 90 18 [0-20] fe c1 [0-20)] f6 e9 90 03 05 09 [0-20] 30 06 [0-20] 90 18 [0-20] 30 06 ff 45 f8 8b 4d ec be } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}