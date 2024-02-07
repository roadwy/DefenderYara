
rule Ransom_MSIL_Cyborg_SA_MSR{
	meta:
		description = "Ransom:MSIL/Cyborg.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 79 62 6f 72 67 20 42 75 69 6c 64 65 72 20 52 61 6e 73 6f 6d 77 61 72 65 } //02 00  Cyborg Builder Ransomware
		$a_01_1 = {73 79 62 6f 72 67 31 66 69 6e 66 2e 65 78 65 } //01 00  syborg1finf.exe
		$a_01_2 = {67 65 74 5f 53 70 65 63 69 61 6c 44 69 72 65 63 74 6f 72 69 65 73 } //01 00  get_SpecialDirectories
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //01 00  CryptoStreamMode
		$a_01_4 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_5 = {43 72 61 63 6b 65 64 } //01 00  Cracked
		$a_01_6 = {57 61 73 48 65 72 65 } //00 00  WasHere
	condition:
		any of ($a_*)
 
}