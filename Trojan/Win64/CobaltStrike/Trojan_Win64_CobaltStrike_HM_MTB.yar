
rule Trojan_Win64_CobaltStrike_HM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HM!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 50 00 37 00 31 00 2e 00 44 00 4c 00 4c 00 } //01 00  CP71.DLL
		$a_01_1 = {4d 61 72 6b 5c 4e 65 77 56 69 72 75 73 5c 43 50 50 5c 6d 73 65 64 67 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 73 65 64 67 65 2e 70 64 62 } //01 00  Mark\NewVirus\CPP\msedge\x64\Release\msedge.pdb
		$a_01_2 = {45 78 70 6f 72 74 53 70 61 72 74 61 6e 43 6f 6f 6b 69 65 73 } //01 00  ExportSpartanCookies
		$a_01_3 = {6d 73 65 64 67 65 2e 64 6c 6c } //00 00  msedge.dll
	condition:
		any of ($a_*)
 
}