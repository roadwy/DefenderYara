
rule VirTool_Win32_Injector_GS{
	meta:
		description = "VirTool:Win32/Injector.GS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 79 43 6e 65 6c 33 32 76 64 6c 6c 53 58 00 } //01 00 
		$a_01_1 = {43 72 65 42 66 65 46 69 6c 65 41 72 46 57 53 71 6e 6f 72 46 5a 00 } //01 00 
		$a_01_2 = {52 65 61 4f 6d 69 6c 65 45 52 00 } //02 00 
		$a_01_3 = {66 a1 f0 e1 00 10 0f bf c8 66 a1 08 e2 00 10 88 c2 66 a1 20 e1 00 10 88 d3 28 c3 88 d8 88 84 0d a1 fc ff ff c7 85 78 fd ff ff 06 01 00 00 } //00 00 
		$a_00_4 = {80 10 00 } //00 63 
	condition:
		any of ($a_*)
 
}