
rule Trojan_Win32_Startpage_QF{
	meta:
		description = "Trojan:Win32/Startpage.QF,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 6f 31 32 33 2e 63 6f 6d 2f 69 6e 64 65 78 6b 2e 68 74 6d } //03 00 
		$a_01_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 6c 70 6f 72 65 72 } //03 00 
		$a_01_2 = {2e 69 63 77 22 22 22 2c 30 } //00 00 
	condition:
		any of ($a_*)
 
}