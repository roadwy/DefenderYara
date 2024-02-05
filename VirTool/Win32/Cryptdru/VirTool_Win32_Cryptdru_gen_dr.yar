
rule VirTool_Win32_Cryptdru_gen_dr{
	meta:
		description = "VirTool:Win32/Cryptdru.gen!dr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 24 6a 01 6a 01 ff 15 90 01 04 83 e8 63 0f 80 90 01 01 05 00 00 50 8b 55 dc 52 6a 64 ff 15 90 01 04 6a 01 ff 15 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 ff ff ff 08 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}