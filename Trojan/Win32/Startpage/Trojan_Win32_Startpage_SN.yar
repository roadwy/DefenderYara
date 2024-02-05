
rule Trojan_Win32_Startpage_SN{
	meta:
		description = "Trojan:Win32/Startpage.SN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 65 74 44 65 66 61 75 6c 74 4b 4b } //03 00 
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 31 00 6f 00 72 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 } //02 00 
		$a_01_2 = {43 6d 64 47 65 74 53 69 67 6e } //02 00 
		$a_01_3 = {4d 44 4c 47 6c 6f 62 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}