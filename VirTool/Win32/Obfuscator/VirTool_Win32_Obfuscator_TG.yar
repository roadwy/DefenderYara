
rule VirTool_Win32_Obfuscator_TG{
	meta:
		description = "VirTool:Win32/Obfuscator.TG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {fc 31 c9 49 89 ca 31 c0 31 db 3e ac 32 c1 88 e9 88 d5 88 f2 b6 08 66 d1 eb 66 d1 d8 } //01 00 
		$a_00_1 = {f7 d2 f7 d1 89 d0 c1 c0 10 66 89 c8 5a 39 c2 74 0b } //01 00 
		$a_02_2 = {8b 13 85 d2 74 30 8b 4a fc 4e 7c 2a 39 ce 7d 26 85 ff 7e 22 29 f1 39 cf 7e 02 89 cf 29 f9 01 f2 8d 04 17 e8 90 01 04 8b 13 89 d8 8b 52 fc 29 fa e8 90 00 } //01 00 
		$a_00_3 = {bf cc cc cc 0c 8a 1e 46 80 fb 20 74 f8 b5 00 80 fb 2d 74 62 80 fb 2b 74 5f 80 fb 24 74 5f 80 fb 78 74 5a 80 fb 58 74 55 80 fb 30 75 13 8a 1e 46 80 fb 78 74 48 80 fb 58 74 43 84 db 74 20 eb 04 } //00 00 
	condition:
		any of ($a_*)
 
}