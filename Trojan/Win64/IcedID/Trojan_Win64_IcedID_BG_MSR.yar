
rule Trojan_Win64_IcedID_BG_MSR{
	meta:
		description = "Trojan:Win64/IcedID.BG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 51 79 51 6e 63 48 71 76 52 71 78 51 59 } //02 00  AQyQncHqvRqxQY
		$a_01_1 = {43 68 47 71 52 72 42 52 68 47 66 4b 55 72 } //02 00  ChGqRrBRhGfKUr
		$a_01_2 = {44 70 66 76 45 6b 49 55 6d 41 72 71 56 6a 4e 6e } //02 00  DpfvEkIUmArqVjNn
		$a_01_3 = {47 5a 77 63 6a 6d 41 66 45 74 4b 47 55 56 76 53 } //02 00  GZwcjmAfEtKGUVvS
		$a_01_4 = {4b 6c 76 52 67 74 53 6d 68 4a 5a 78 64 48 76 } //02 00  KlvRgtSmhJZxdHv
		$a_01_5 = {4e 6b 62 62 79 63 53 42 69 70 69 } //02 00  NkbbycSBipi
		$a_01_6 = {52 4c 72 6f 47 57 55 6b 58 6d 7a } //02 00  RLroGWUkXmz
		$a_01_7 = {55 47 72 59 4c 50 4e 6e 4f 51 5a 57 7a 6f 56 6e } //00 00  UGrYLPNnOQZWzoVn
	condition:
		any of ($a_*)
 
}