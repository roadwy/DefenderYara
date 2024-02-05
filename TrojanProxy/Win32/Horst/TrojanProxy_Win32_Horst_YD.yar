
rule TrojanProxy_Win32_Horst_YD{
	meta:
		description = "TrojanProxy:Win32/Horst.YD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 10 8a ca 3a 17 75 1c 84 c9 74 14 8a 50 01 8a ca 3a 57 01 75 0e 83 c0 02 83 c7 02 84 c9 75 e0 33 c0 eb 05 1b c0 } //01 00 
		$a_01_1 = {8a 4f 01 47 84 c9 75 f8 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 6a 00 f3 a4 ff d5 6a 00 ff d5 6a 00 ff d5 } //01 00 
		$a_03_2 = {c7 44 24 10 30 75 00 00 ff d6 6a 00 ff d6 6a 00 ff d6 90 02 20 50 68 06 10 00 00 68 ff ff 00 00 57 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}