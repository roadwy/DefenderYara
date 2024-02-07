
rule Trojan_Win64_Winnti_ZC_dha{
	meta:
		description = "Trojan:Win64/Winnti.ZC!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 40 c0 80 00 00 00 44 8d 46 01 45 33 c9 ba 00 00 00 80 89 70 20 40 b7 99 c7 40 b8 04 00 00 00 ff 15 } //01 00 
		$a_01_1 = {40 30 3b 48 ff c3 40 fe c7 48 ff c9 75 } //01 00 
		$a_01_2 = {49 49 53 46 69 6c 74 65 72 36 34 2e 64 6c 6c } //01 00  IISFilter64.dll
		$a_01_3 = {47 65 74 46 69 6c 74 65 72 56 65 72 73 69 6f 6e } //01 00  GetFilterVersion
		$a_01_4 = {48 74 74 70 46 69 6c 74 65 72 50 72 6f 63 } //01 00  HttpFilterProc
		$a_01_5 = {54 65 72 6d 69 6e 61 74 65 46 69 6c 74 65 72 } //00 00  TerminateFilter
	condition:
		any of ($a_*)
 
}