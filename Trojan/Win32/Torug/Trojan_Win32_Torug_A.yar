
rule Trojan_Win32_Torug_A{
	meta:
		description = "Trojan:Win32/Torug.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 2d 80 b4 05 90 01 04 09 40 83 f8 05 72 f2 57 57 57 56 ff 15 90 01 03 00 57 8d 45 90 01 01 50 6a 05 8d 85 90 1b 00 50 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}