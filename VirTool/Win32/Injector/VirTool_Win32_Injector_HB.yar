
rule VirTool_Win32_Injector_HB{
	meta:
		description = "VirTool:Win32/Injector.HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 2f 0f d8 f0 90 02 10 46 90 02 20 31 f5 66 0f 73 d3 5c 90 02 10 3b ac 24 10 02 00 00 90 00 } //01 00 
		$a_03_1 = {31 32 66 0f fd d2 90 02 20 83 c2 04 0f d5 c1 90 02 15 39 5a fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}