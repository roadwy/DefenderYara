
rule Trojan_BAT_CrimsonRAT_A_MSR{
	meta:
		description = "Trojan:BAT/CrimsonRAT.A!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 70 00 67 00 7c 00 38 00 32 00 39 00 32 00 } //01 00  jpg|8292
		$a_01_1 = {52 00 68 00 61 00 72 00 62 00 77 00 64 00 } //01 00  Rharbwd
		$a_01_2 = {6e 00 74 00 68 00 61 00 72 00 70 00 72 00 6d 00 65 00 73 00 } //01 00  ntharprmes
		$a_01_3 = {64 00 72 00 65 00 61 00 6f 00 6d 00 2e 00 7a 00 69 00 70 00 } //01 00  dreaom.zip
		$a_01_4 = {44 65 62 75 67 5c 76 65 72 74 68 69 72 6d 73 2e 70 64 62 } //00 00  Debug\verthirms.pdb
	condition:
		any of ($a_*)
 
}