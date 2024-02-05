
rule Trojan_Win32_Fareit_CZ_eml{
	meta:
		description = "Trojan:Win32/Fareit.CZ!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 1c 10 8a 1b 80 f3 3e 8d 34 02 88 1e 42 49 75 ef } //00 00 
	condition:
		any of ($a_*)
 
}