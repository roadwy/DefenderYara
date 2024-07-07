
rule VirTool_Win32_Injector_gen_FO{
	meta:
		description = "VirTool:Win32/Injector.gen!FO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {52 65 72 6e 51 6c 33 32 2e 64 6c 6c } //1 RernQl32.dll
		$a_00_1 = {53 72 65 61 74 64 46 69 6c 65 41 4e 55 } //1 SreatdFileANU
		$a_00_2 = {52 66 61 64 46 69 6c 65 41 66 6b } //1 RfadFileAfk
		$a_01_3 = {0f b6 8c 04 20 06 00 00 8b 94 24 40 05 00 00 8b b4 24 78 08 00 00 89 84 24 10 01 00 00 89 d0 99 f7 fe 8b 84 24 84 08 00 00 0f b6 04 10 31 c1 88 cb 8b 84 24 10 01 00 00 88 9c 04 20 06 00 00 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*3) >=6
 
}