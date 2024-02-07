
rule Trojan_Win32_Airostor_B{
	meta:
		description = "Trojan:Win32/Airostor.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 2d 01 00 8d 4d a4 0f 90 01 02 00 00 00 0f bf c0 50 51 90 00 } //02 00 
		$a_01_1 = {67 00 2e 00 61 00 73 00 70 00 3f 00 6d 00 61 00 63 00 3d 00 } //02 00  g.asp?mac=
		$a_01_2 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 31 00 6f 00 72 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 } //01 00  \Internet Exp1orer.lnk
		$a_01_3 = {69 00 75 00 75 00 71 00 3b 00 30 00 30 00 } //01 00  iuuq;00
		$a_01_4 = {4d 00 79 00 69 00 51 00 2e 00 65 00 78 00 65 00 } //01 00  MyiQ.exe
		$a_01_5 = {62 00 65 00 6e 00 6a 00 6f 00 } //00 00  benjo
	condition:
		any of ($a_*)
 
}