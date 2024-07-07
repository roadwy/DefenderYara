
rule VirTool_Win32_Obfuscator_OA_MTB{
	meta:
		description = "VirTool:Win32/Obfuscator.OA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 85 30 fe ff ff 81 45 88 90 01 04 81 6d ac 90 01 04 81 85 34 ff ff ff 90 01 04 8b 4d 08 03 4d 0c 0f be 11 0f b6 85 63 ff ff ff 33 d0 8b 4d 08 03 4d 0c 88 11 8b 55 0c 83 ea 01 89 55 0c e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}