
rule VirTool_Win32_Pharos_A{
	meta:
		description = "VirTool:Win32/Pharos.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8b 4c 24 2c 89 08 8b 4c 24 20 89 48 04 c7 40 08 40 00 00 00 8b 4c 24 28 89 48 0c 8b 0d 4c ed 54 00 89 0c 24 89 44 24 04 c7 44 24 08 04 00 00 00 c7 44 24 0c 04 00 00 00 e8 90 01 04 8b 44 24 10 85 c0 90 01 02 8b 54 24 24 8b 02 ff 90 01 01 83 c4 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}