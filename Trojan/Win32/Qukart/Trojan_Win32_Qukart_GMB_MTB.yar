
rule Trojan_Win32_Qukart_GMB_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 45 78 49 42 7a 58 6d 5a 34 } //01 00  AExIBzXmZ4
		$a_01_1 = {75 69 41 6e 6e 50 68 55 } //01 00  uiAnnPhU
		$a_01_2 = {58 62 51 55 6c 4a 73 56 } //01 00  XbQUlJsV
		$a_01_3 = {47 6a 59 4a 4c 64 67 68 } //01 00  GjYJLdgh
		$a_01_4 = {4c 6d 72 4a 6c 64 42 66 } //00 00  LmrJldBf
	condition:
		any of ($a_*)
 
}