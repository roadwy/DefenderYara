
rule Trojan_Win64_BazarLoader_QA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {c6 45 e5 05 c6 45 e6 14 c6 45 e7 2f c6 45 e8 10 c6 45 e9 05 c6 45 ea 0e c6 45 eb 26 c6 45 ec 09 c6 45 ed 0c c6 45 ee 05 c6 45 ef 2e c6 45 f0 01 c6 45 f1 0d c6 45 f2 05 c6 45 f3 21 88 45 f4 } //03 00 
		$a_80_1 = {57 54 4c 5f 43 6d 64 42 61 72 5f 49 6e 74 65 72 6e 61 6c 41 75 74 6f 50 6f 70 75 70 4d 73 67 } //WTL_CmdBar_InternalAutoPopupMsg  03 00 
		$a_80_2 = {4d 6f 64 75 6c 65 5f 52 61 77 } //Module_Raw  03 00 
		$a_80_3 = {47 65 74 4f 70 65 6e 46 69 6c 65 4e 61 6d 65 41 } //GetOpenFileNameA  03 00 
		$a_80_4 = {57 54 4c 5f 43 6f 6d 6d 61 6e 64 42 61 72 } //WTL_CommandBar  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_QA_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 8b 49 f8 49 ff ca 41 8b 11 49 03 ce 45 8b 41 fc 48 03 d6 4d 85 c0 74 19 0f 1f 80 00 00 00 00 0f b6 02 48 ff c2 88 01 48 8d 49 01 49 83 e8 01 75 ee 49 83 c1 28 4d 85 d2 75 c5 } //00 00 
	condition:
		any of ($a_*)
 
}