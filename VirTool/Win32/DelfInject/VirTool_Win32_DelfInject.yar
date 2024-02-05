
rule VirTool_Win32_DelfInject{
	meta:
		description = "VirTool:Win32/DelfInject,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 06 40 00 00 68 99 99 99 c5 68 9a 99 99 99 68 16 89 53 40 68 0c 02 2b 87 68 5c c7 6b 40 68 8f c2 f5 28 68 a9 c9 57 40 68 8b 6c e7 fb 68 3d ea 6c 40 68 0a d7 a3 70 68 c0 0a 5c 40 68 98 6e 12 83 33 d2 33 c0 e8 1e 02 00 00 e9 72 ff ff ff e9 d4 fd ff ff f8 fc 42 66 c1 c7 b0 0b db f5 e9 c5 fd ff ff 33 c0 5a 59 59 64 89 10 68 d1 29 40 00 8d 45 f4 ba 03 00 00 00 e8 33 eb ff ff c3 e9 d9 e8 ff ff eb eb } //00 00 
	condition:
		any of ($a_*)
 
}