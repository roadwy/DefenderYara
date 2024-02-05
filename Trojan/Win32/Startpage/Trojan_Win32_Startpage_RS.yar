
rule Trojan_Win32_Startpage_RS{
	meta:
		description = "Trojan:Win32/Startpage.RS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2a d8 32 5c 24 90 01 01 8a 44 14 90 01 01 88 9c 14 90 01 02 00 00 42 88 44 24 90 01 01 3a c1 75 de 90 09 4d 00 88 8c 14 90 01 02 00 00 88 44 24 90 01 01 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 88 4c 24 90 01 01 33 d2 88 44 24 90 01 01 8d 49 00 8a c2 b3 90 01 01 f6 eb b3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}