
rule VirTool_Win32_Remeshelsz_A{
	meta:
		description = "VirTool:Win32/Remeshelsz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ec 04 a3 d8 61 40 00 a1 d0 61 40 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 10 00 00 00 c7 44 24 04 d4 61 40 00 89 04 24 a1 90 01 06 83 ec 1c 90 00 } //01 00 
		$a_03_1 = {c7 44 24 08 44 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 62 40 00 90 01 05 c7 05 00 62 40 90 01 05 c7 05 2c 62 40 90 01 05 a1 d0 61 40 00 a3 90 01 04 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}