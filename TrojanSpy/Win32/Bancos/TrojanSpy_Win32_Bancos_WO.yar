
rule TrojanSpy_Win32_Bancos_WO{
	meta:
		description = "TrojanSpy:Win32/Bancos.WO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 6c 6f 71 75 65 61 64 6f 72 20 64 65 20 50 6f 70 2d 75 70 73 } //01 00  Bloqueador de Pop-ups
		$a_00_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //01 00  explorerbar
		$a_00_2 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73 } //01 00 
		$a_00_3 = {6d 61 69 6c 20 66 72 6f 6d 3a 3c } //01 00  mail from:<
		$a_00_4 = {4f 6e 44 6f 77 6e 6c 6f 61 64 43 6f 6d 70 6c 65 74 65 } //01 00  OnDownloadComplete
		$a_00_5 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 74 79 70 65 64 75 72 6c 73 } //01 00  software\microsoft\internet explorer\typedurls
		$a_00_6 = {53 6f 62 72 65 6f 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 } //01 00  SobreoInternetExplorer
		$a_00_7 = {65 73 20 64 61 20 69 6e 74 65 72 6e 65 74 2e 2e 2e } //01 00  es da internet...
		$a_00_8 = {63 6f 6e 66 69 72 6d 65 } //01 00  confirme
		$a_00_9 = {2e 63 6f 6d 2e 62 72 } //02 00  .com.br
		$a_01_10 = {74 39 7a 54 43 55 66 49 71 52 2b 44 79 56 48 6a 2b 4d 74 79 67 44 00 } //02 00 
		$a_01_11 = {49 68 52 42 4a 38 51 6c 45 61 66 2f 62 6e 5a 50 66 4b 30 47 30 76 43 00 } //02 00  桉䉒㡊汑慅⽦湢做䭦䜰瘰C
		$a_01_12 = {51 39 35 53 61 46 6c 6a 31 68 63 59 63 30 5a 4c 2f 33 55 76 4b 55 36 58 00 } //00 00 
	condition:
		any of ($a_*)
 
}