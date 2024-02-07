
rule Trojan_Win32_Zbot_WQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 54 39 ff d0 c2 80 f2 7e 88 54 39 ff 49 83 f9 00 75 ed } //0a 00 
		$a_02_1 = {56 33 de 33 f3 33 de 5e 81 c3 90 01 04 83 ec 90 01 01 c7 04 24 90 01 04 54 68 32 01 00 00 83 ec 90 01 01 89 3c 24 83 ec 90 01 01 89 04 24 ff 13 8d 07 8b 40 90 01 01 03 c7 8b 40 29 90 00 } //01 00 
		$a_01_2 = {4a 52 68 72 2e 64 6c 68 64 75 73 65 } //00 00  JRhr.dlhduse
	condition:
		any of ($a_*)
 
}