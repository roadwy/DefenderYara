
rule Trojan_Win32_Startpage_EJ{
	meta:
		description = "Trojan:Win32/Startpage.EJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 74 6a 2e 6b 65 79 35 31 38 38 2e 63 6f 6d } //01 00 
		$a_03_1 = {33 c0 55 68 90 01 02 40 00 64 ff 30 64 89 20 b8 90 01 02 40 00 ba 90 01 02 40 00 e8 90 01 02 ff ff 6a 00 68 90 01 02 40 00 a1 90 01 02 40 00 e8 90 01 02 ff ff 50 68 90 01 02 40 00 68 90 01 02 40 00 6a 00 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}