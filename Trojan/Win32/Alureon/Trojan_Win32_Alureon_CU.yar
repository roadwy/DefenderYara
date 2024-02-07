
rule Trojan_Win32_Alureon_CU{
	meta:
		description = "Trojan:Win32/Alureon.CU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 7f 8d 45 e4 50 6a 00 6a 01 53 ff 15 90 00 } //01 00 
		$a_01_1 = {50 6a 5a 53 ff d7 8d 45 } //01 00 
		$a_01_2 = {67 61 73 66 6b 79 } //00 00  gasfky
	condition:
		any of ($a_*)
 
}