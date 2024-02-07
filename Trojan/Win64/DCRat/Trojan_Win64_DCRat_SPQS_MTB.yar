
rule Trojan_Win64_DCRat_SPQS_MTB{
	meta:
		description = "Trojan:Win64/DCRat.SPQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 72 00 65 00 65 00 31 00 34 00 35 00 39 00 2e 00 68 00 6f 00 73 00 74 00 2e 00 6f 00 64 00 2e 00 75 00 61 00 2f 00 52 00 75 00 73 00 74 00 43 00 68 00 65 00 61 00 74 00 43 00 68 00 65 00 63 00 6b 00 2e 00 65 00 78 00 65 00 } //01 00  http://free1459.host.od.ua/RustCheatCheck.exe
		$a_01_1 = {52 75 73 74 43 68 65 61 74 43 68 65 63 6b 2e 70 64 62 } //00 00  RustCheatCheck.pdb
	condition:
		any of ($a_*)
 
}