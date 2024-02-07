
rule Trojan_WinNT_Adwind_AA{
	meta:
		description = "Trojan:WinNT/Adwind.AA,SIGNATURE_TYPE_JAVAHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 50 4b 6e 70 57 63 76 44 74 5a 55 55 54 59 4a 50 58 6e 4f 4e 64 54 57 4f 6e 51 75 73 61 50 6a 61 51 65 70 58 58 4b 4b 6d 75 48 6a 44 69 47 59 6b 59 56 50 69 66 42 6c 77 43 79 4b 62 63 78 79 49 67 64 74 77 72 51 66 59 49 71 73 4e 70 75 } //01 00  rPKnpWcvDtZUUTYJPXnONdTWOnQusaPjaQepXXKKmuHjDiGYkYVPifBlwCyKbcxyIgdtwrQfYIqsNpu
		$a_01_1 = {4b 74 48 67 67 48 51 63 46 59 44 62 74 54 75 46 52 41 58 48 52 58 55 66 77 4c } //00 00  KtHggHQcFYDbtTuFRAXHRXUfwL
	condition:
		any of ($a_*)
 
}