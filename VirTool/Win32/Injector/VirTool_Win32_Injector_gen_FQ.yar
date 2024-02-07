
rule VirTool_Win32_Injector_gen_FQ{
	meta:
		description = "VirTool:Win32/Injector.gen!FQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 65 72 6e 65 6c 75 32 2e 64 6c 6c 4a 58 4f 72 76 4f 49 } //01 00  wernelu2.dllJXOrvOI
		$a_00_1 = {43 49 65 61 48 47 46 69 6c 65 41 } //01 00  CIeaHGFileA
		$a_00_2 = {52 65 61 64 4d 69 6c 65 6c 6a 44 4f 42 70 } //03 00  ReadMileljDOBp
		$a_01_3 = {89 d0 03 45 14 8a 00 31 c8 88 03 8b 85 5c ff ff ff 89 c3 03 9d e4 fe ff ff 8b 85 5c ff ff ff 03 85 e4 fe ff ff 8a 08 8b 85 5c ff ff ff 99 f7 bd 3c ff ff ff 89 d0 03 45 14 8a 00 31 c8 88 03 } //01 00 
		$a_00_4 = {5d 04 00 } //00 6a 
	condition:
		any of ($a_*)
 
}