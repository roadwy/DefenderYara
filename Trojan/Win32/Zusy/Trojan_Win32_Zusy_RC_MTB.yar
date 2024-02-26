
rule Trojan_Win32_Zusy_RC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 48 3e 00 00 50 b8 cb 6d 00 00 b8 2f 18 00 00 58 58 52 ba da 16 00 00 51 b9 55 78 00 00 b9 0f 22 00 00 59 5a 52 52 ba 79 18 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 6a 02 e8 90 01 02 fe ff 6a 02 6a 00 6a 02 e8 90 01 02 fe ff 6a 02 6a 00 6a 02 e8 90 01 02 fe ff 90 00 } //01 00 
		$a_01_1 = {6a 68 53 37 68 34 48 73 59 33 67 68 36 35 68 73 57 33 33 33 34 } //01 00  jhS7h4HsY3gh65hsW3334
		$a_01_2 = {43 43 43 20 43 72 79 70 74 65 72 } //01 00  CCC Crypter
		$a_01_3 = {58 45 41 5a 45 52 54 41 43 51 } //00 00  XEAZERTACQ
	condition:
		any of ($a_*)
 
}