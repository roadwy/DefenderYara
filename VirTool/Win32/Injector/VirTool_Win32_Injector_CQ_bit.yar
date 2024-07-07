
rule VirTool_Win32_Injector_CQ_bit{
	meta:
		description = "VirTool:Win32/Injector.CQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 6a 40 68 00 60 00 00 68 80 68 41 00 ff 15 90 01 03 00 51 53 8d 05 90 01 03 00 33 c9 8a 1c 08 80 f3 bb f6 d3 80 f3 84 88 1c 08 41 81 f9 51 5f 00 00 75 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}