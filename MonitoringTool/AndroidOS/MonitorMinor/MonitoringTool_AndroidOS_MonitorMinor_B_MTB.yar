
rule MonitoringTool_AndroidOS_MonitorMinor_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MonitorMinor.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f0 b5 03 af 4d f8 04 8d 11 46 1c 46 05 46 ff f7 ?? ff 28 68 21 46 d0 f8 ac 22 28 46 90 90 47 80 46 28 68 21 46 00 22 d0 f8 78 33 28 46 98 47 06 46 42 46 31 46 ff f7 ?? ff 28 68 21 46 32 46 00 23 d0 f8 7c c3 28 46 e0 47 00 20 5d f8 04 8b f0 bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}