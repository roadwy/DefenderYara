
rule Trojan_Win32_Parchood_A{
	meta:
		description = "Trojan:Win32/Parchood.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c2 34 06 00 00 90 03 03 02 ff 32 5b 8b 1a 33 c3 83 e1 01 33 04 8d 90 01 02 00 10 90 00 } //01 00 
		$a_03_1 = {10 ab 49 75 f6 c7 05 00 90 01 01 00 10 70 02 00 00 c2 04 00 90 09 05 00 f7 25 04 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}