
rule Trojan_Win32_Emotet_DAM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_81_0 = {45 4d 4f 54 45 54 } //01 00  EMOTET
		$a_81_1 = {65 47 4e 6b 5a 67 3d } //01 00  eGNkZg=
		$a_81_2 = {49 6d 61 67 65 2e 62 6d 70 } //01 00  Image.bmp
		$a_01_3 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 43 00 52 00 59 00 50 00 54 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 } //02 00  C:\WINDOWS\SYSTEM32\CRYPT32.DLL
		$a_01_4 = {45 00 4d 00 4f 00 54 00 45 00 54 00 } //01 00  EMOTET
		$a_01_5 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 65 00 6e 00 74 00 65 00 72 00 20 00 61 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 2e 00 } //00 00  Please enter a currency.
	condition:
		any of ($a_*)
 
}