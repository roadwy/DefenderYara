
rule VirTool_Win32_Obfuscator_AOF{
	meta:
		description = "VirTool:Win32/Obfuscator.AOF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 50 8b 45 08 03 45 fc 0f b6 00 50 e8 ?? ?? ff ff 59 59 8b 4d 08 03 4d fc 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}