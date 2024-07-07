
rule VirTool_Win32_DelfInject_AY{
	meta:
		description = "VirTool:Win32/DelfInject.AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f8 8a 84 9d 90 01 04 8b 94 bd 90 01 04 89 94 9d 90 01 04 25 ff 00 00 00 89 84 bd 90 01 04 8b 45 08 33 d2 52 50 8b 84 9d 90 01 04 03 84 bd 90 01 04 99 e8 90 01 04 8a 84 85 90 01 04 30 06 46 ff 4d f0 75 90 00 } //1
		$a_03_1 = {68 00 01 00 00 b9 90 01 04 ba 20 00 00 00 b8 11 5a 00 00 e8 90 01 04 e8 90 01 04 8d 95 90 01 04 b9 90 01 04 8b c3 e8 90 01 04 03 1d 90 01 04 89 5d fc 90 01 04 ff 75 fc c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}