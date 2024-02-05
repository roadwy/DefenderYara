
rule Trojan_Win32_Sirefef_C{
	meta:
		description = "Trojan:Win32/Sirefef.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4 } //01 00 
		$a_01_1 = {eb 0b 81 38 78 56 4f 23 74 09 8b 40 04 3b c3 75 f1 eb 03 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_C_2{
	meta:
		description = "Trojan:Win32/Sirefef.C,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4 } //01 00 
		$a_01_1 = {eb 0b 81 38 78 56 4f 23 74 09 8b 40 04 3b c3 75 f1 eb 03 } //00 00 
	condition:
		any of ($a_*)
 
}