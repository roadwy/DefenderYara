
rule TrojanDropper_Win32_Cutwail_AR{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 ec 8d 45 fc 50 6a 04 ff 75 f0 ff 75 ec 90 09 01 00 (89|8f) } //1
		$a_01_1 = {25 00 00 ff ff c1 e2 09 } //1
		$a_01_2 = {80 38 90 74 01 40 83 ec 08 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}