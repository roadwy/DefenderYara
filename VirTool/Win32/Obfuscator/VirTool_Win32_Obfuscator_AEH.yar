
rule VirTool_Win32_Obfuscator_AEH{
	meta:
		description = "VirTool:Win32/Obfuscator.AEH,SIGNATURE_TYPE_PEHSTR_EXT,32 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 fe 80 38 01 00 76 0c 81 bd 90 01 01 fb ff ff 0c 75 cd 01 77 90 00 } //01 00 
		$a_00_1 = {32 c0 88 95 08 fc ff ff 88 9d 09 fc ff ff 33 c9 38 94 0d fc fb ff ff 75 0b 38 9c 0d fd fb ff ff 75 02 b0 01 38 94 0d fd fb ff ff 75 0b 38 9c 0d fe fb ff ff 75 02 b0 01 38 94 0d fe fb ff ff 75 0b 38 9c 0d ff fb ff ff 75 02 b0 01 38 94 0d ff fb ff ff 75 0b 38 9c 0d 00 fc ff ff 75 02 b0 01 38 94 0d 00 fc ff ff 75 0b 38 9c 0d 01 fc ff ff 75 02 b0 01 83 c1 05 81 f9 f4 01 00 00 } //01 00 
		$a_02_2 = {84 c0 74 1d a1 90 01 01 97 40 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 01 97 40 00 c1 e8 10 32 04 37 88 06 83 c6 01 83 ad 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}