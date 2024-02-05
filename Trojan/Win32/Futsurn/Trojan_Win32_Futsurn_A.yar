
rule Trojan_Win32_Futsurn_A{
	meta:
		description = "Trojan:Win32/Futsurn.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 02 75 e3 56 8b cd e8 90 01 02 00 00 eb d9 5f 90 00 } //01 00 
		$a_01_1 = {81 7d c0 00 0c ee 92 75 0a 6a 02 ff 75 e4 } //00 00 
	condition:
		any of ($a_*)
 
}