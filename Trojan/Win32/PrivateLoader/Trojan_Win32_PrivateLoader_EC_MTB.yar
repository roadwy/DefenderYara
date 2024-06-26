
rule Trojan_Win32_PrivateLoader_EC_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 41 54 54 43 2e 53 59 53 } //01 00  BATTC.SYS
		$a_81_1 = {5f 50 4c 65 57 49 46 2d 50 45 42 } //01 00  _PLeWIF-PEB
		$a_01_2 = {41 56 49 20 4c 49 53 54 } //01 00  AVI LIST
		$a_01_3 = {68 64 72 6c 61 76 69 68 38 } //01 00  hdrlavih8
		$a_01_4 = {54 00 68 00 65 00 6d 00 69 00 64 00 61 00 } //01 00  Themida
		$a_01_5 = {41 00 63 00 72 00 6f 00 43 00 45 00 46 00 2e 00 65 00 78 00 65 00 } //01 00  AcroCEF.exe
		$a_01_6 = {32 00 31 00 2e 00 37 00 2e 00 32 00 30 00 30 00 39 00 39 00 2e 00 34 00 35 00 34 00 39 00 37 00 39 00 } //00 00  21.7.20099.454979
	condition:
		any of ($a_*)
 
}