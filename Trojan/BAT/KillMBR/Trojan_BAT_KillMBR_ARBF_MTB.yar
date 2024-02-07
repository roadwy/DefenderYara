
rule Trojan_BAT_KillMBR_ARBF_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 4d 61 6c 77 61 72 65 4b 61 62 6f 6f 6d 5c 4d 61 6c 77 61 72 65 4b 61 62 6f 6f 6d 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4d 61 6c 77 61 72 65 4b 61 62 6f 6f 6d 2e 70 64 62 } //02 00  \MalwareKaboom\MalwareKaboom\obj\Release\MalwareKaboom.pdb
		$a_01_1 = {59 6f 75 20 6d 75 73 74 20 67 69 76 65 20 75 73 20 31 30 24 20 4c 54 43 20 61 74 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 61 64 64 72 65 73 73 3a 20 4c 62 6f 6d 62 39 64 37 6e 37 68 4e 6e 71 4e 41 42 36 35 48 56 67 72 6b 35 70 43 7a 47 37 35 39 68 35 } //00 00  You must give us 10$ LTC at the following address: Lbomb9d7n7hNnqNAB65HVgrk5pCzG759h5
	condition:
		any of ($a_*)
 
}