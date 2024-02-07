
rule VirTool_Win32_VBInject_gen_MS{
	meta:
		description = "VirTool:Win32/VBInject.gen!MS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 11 8b 4d d8 8b 42 0c 8b 95 58 ff ff ff 8a 0c 11 8b 95 2c ff ff ff 32 0c 10 8b 95 28 ff ff ff 88 0c 10 8b 4d a8 b8 01 00 00 00 03 c1 } //01 00 
		$a_00_1 = {56 00 69 00 78 00 20 00 50 00 4f 00 4c 00 45 00 4d 00 44 00 20 00 4b 00 49 00 5c 00 42 00 65 00 6e 00 69 00 78 00 76 00 69 00 78 00 2e 00 76 00 62 00 70 00 } //00 00  Vix POLEMD KI\Benixvix.vbp
	condition:
		any of ($a_*)
 
}