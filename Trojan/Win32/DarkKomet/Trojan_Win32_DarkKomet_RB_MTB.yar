
rule Trojan_Win32_DarkKomet_RB_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 54 00 7a 00 51 00 70 00 42 00 70 00 6d 00 67 00 79 00 76 00 53 00 43 00 4d 00 53 00 } //01 00  ATzQpBpmgyvSCMS
		$a_01_1 = {72 00 68 00 76 00 46 00 6f 00 6f 00 62 00 63 00 43 00 4c 00 } //01 00  rhvFoobcCL
		$a_01_2 = {44 00 68 00 4c 00 4a 00 72 00 67 00 } //01 00  DhLJrg
		$a_01_3 = {43 00 6e 00 75 00 42 00 52 00 74 00 73 00 49 00 79 00 41 00 } //01 00  CnuBRtsIyA
		$a_01_4 = {4d 00 73 00 6e 00 6f 00 6d 00 72 00 63 00 56 00 64 00 47 00 69 00 53 00 6a 00 6e 00 71 00 } //01 00  MsnomrcVdGiSjnq
		$a_01_5 = {38 00 62 00 6c 00 78 00 78 00 2e 00 65 00 78 00 65 00 } //00 00  8blxx.exe
	condition:
		any of ($a_*)
 
}