
rule Trojan_WinNT_Sirefef_gen_C{
	meta:
		description = "Trojan:WinNT/Sirefef.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 0a 6b c0 ?? 80 e1 df 0f be f1 33 c6 42 84 c9 75 ee } //1
		$a_00_1 = {49 00 44 00 45 00 5c 00 5b 00 63 00 6d 00 7a 00 20 00 76 00 6d 00 6b 00 64 00 5d 00 00 00 } //1
		$a_03_2 = {68 56 01 00 c0 ff 75 fc ff 15 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 8b 75 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule Trojan_WinNT_Sirefef_gen_C_2{
	meta:
		description = "Trojan:WinNT/Sirefef.gen!C,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 0a 6b c0 ?? 80 e1 df 0f be f1 33 c6 42 84 c9 75 ee } //1
		$a_00_1 = {49 00 44 00 45 00 5c 00 5b 00 63 00 6d 00 7a 00 20 00 76 00 6d 00 6b 00 64 00 5d 00 00 00 } //1
		$a_03_2 = {68 56 01 00 c0 ff 75 fc ff 15 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 8b 75 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}