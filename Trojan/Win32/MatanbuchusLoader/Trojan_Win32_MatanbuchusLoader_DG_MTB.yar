
rule Trojan_Win32_MatanbuchusLoader_DG_MTB{
	meta:
		description = "Trojan:Win32/MatanbuchusLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 42 6f 65 51 52 49 77 2e 64 6c 6c } //01 00  EBoeQRIw.dll
		$a_01_1 = {44 76 4d 4f 49 57 68 39 4c 4f } //01 00  DvMOIWh9LO
		$a_01_2 = {45 68 67 59 4c 34 44 } //01 00  EhgYL4D
		$a_01_3 = {46 6f 56 6b 58 38 47 6e 34 } //01 00  FoVkX8Gn4
		$a_01_4 = {4d 5a 34 48 6b 52 48 70 4a } //01 00  MZ4HkRHpJ
		$a_01_5 = {59 62 74 41 57 4d 54 63 48 59 } //01 00  YbtAWMTcHY
		$a_01_6 = {66 44 4e 41 61 50 64 31 72 79 72 } //00 00  fDNAaPd1ryr
	condition:
		any of ($a_*)
 
}