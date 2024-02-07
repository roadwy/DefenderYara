
rule VirTool_Win32_VBInject_QH{
	meta:
		description = "VirTool:Win32/VBInject.QH,SIGNATURE_TYPE_PEHSTR,32 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 43 00 3a 00 5c 00 53 00 74 00 75 00 62 00 31 00 5c 00 } //02 00  \AC:\Stub1\
		$a_01_1 = {75 08 dc 35 a8 11 40 00 eb 11 ff 35 ac 11 40 00 ff 35 a8 11 40 00 e8 } //01 00 
		$a_01_2 = {c7 85 f0 fd ff ff 08 00 00 00 c7 45 98 54 00 00 00 c7 45 90 02 00 00 00 8d 45 90 50 8d 45 80 50 e8 } //01 00 
		$a_01_3 = {c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 00 8b 45 08 8b 00 ff 75 08 ff 50 04 c7 45 fc 01 00 00 00 8b 45 14 83 20 00 c7 45 fc 02 00 00 00 6a ff } //00 00 
	condition:
		any of ($a_*)
 
}