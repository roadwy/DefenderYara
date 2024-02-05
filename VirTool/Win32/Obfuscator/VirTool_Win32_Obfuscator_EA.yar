
rule VirTool_Win32_Obfuscator_EA{
	meta:
		description = "VirTool:Win32/Obfuscator.EA,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8d 45 c8 68 00 00 00 f0 6a 01 6a 00 6a 00 50 ff 15 } //01 00 
		$a_01_1 = {c7 45 e3 4b 65 72 6e be 54 3f f0 bc f7 d2 ba 37 0d e2 26 33 da 8b d6 c7 45 e7 65 6c 33 32 8d 15 fe 7f 8b 24 c1 c7 06 b9 a0 cd fc c6 8d 3d a6 1d 0b 24 c1 c3 1d c7 45 eb 2e 64 6c 6c } //01 00 
		$a_01_2 = {c7 45 cc 56 69 72 74 c1 ef 00 81 c6 1d e7 82 16 bf ed f4 24 94 c7 45 d0 75 61 6c 50 81 c3 ec c8 02 ac 81 c2 30 0a 7a bc 87 ce c7 45 d4 72 6f 74 65 33 fa 89 fe c7 45 d8 63 74 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}