
rule Trojan_O97M_Anorocuriv_AR_MTB{
	meta:
		description = "Trojan:O97M/Anorocuriv.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 39 39 29 20 2b 20 43 68 72 28 35 38 29 20 2b 20 43 68 72 28 39 32 29 20 2b 20 43 68 72 28 37 38 29 20 2b 20 43 68 72 28 38 34 29 20 2b 20 43 68 72 28 39 39 29 20 2b 20 43 68 72 28 31 31 31 29 20 2b 20 43 68 72 28 31 31 34 29 20 2b 20 43 68 72 28 31 30 31 29 } //01 00  Chr(99) + Chr(58) + Chr(92) + Chr(78) + Chr(84) + Chr(99) + Chr(111) + Chr(114) + Chr(101)
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 28 22 63 3a 5c 4e 54 63 6f 72 65 5c 65 61 73 79 2e 63 6d 64 22 } //01 00  CreateFile("c:\NTcore\easy.cmd"
		$a_01_2 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a } //01 00   = GetObject("new:
		$a_01_3 = {2e 52 75 6e 20 22 63 3a 5c 4e 54 63 6f 72 65 5c 65 61 73 79 2e 63 6d 64 22 } //00 00  .Run "c:\NTcore\easy.cmd"
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}