
rule Trojan_BAT_AveMaria_NEAY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {45 44 31 31 38 36 44 46 39 46 36 } //05 00  ED1186DF9F6
		$a_01_1 = {43 32 36 33 37 39 31 46 38 43 34 } //05 00  C263791F8C4
		$a_01_2 = {72 00 74 00 62 00 4c 00 69 00 62 00 72 00 61 00 72 00 69 00 65 00 73 00 2e 00 54 00 65 00 78 00 74 00 } //03 00  rtbLibraries.Text
		$a_01_3 = {67 65 74 5f 4d 65 73 73 61 67 65 43 72 65 61 74 65 4e 50 44 46 46 69 6c 65 73 49 6e 44 69 72 } //03 00  get_MessageCreateNPDFFilesInDir
		$a_01_4 = {52 75 73 73 69 61 56 73 55 6b 72 61 69 6e 65 } //02 00  RussiaVsUkraine
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerHiddenAttribute
	condition:
		any of ($a_*)
 
}