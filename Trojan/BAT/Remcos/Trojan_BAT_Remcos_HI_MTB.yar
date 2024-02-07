
rule Trojan_BAT_Remcos_HI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {65 78 65 2e 6b 63 61 64 2f 74 64 62 61 2f 31 37 31 2e 35 37 31 2e 33 34 2e 39 37 31 2f 2f 3a 70 74 74 68 } //01 00  exe.kcad/tdba/171.571.34.971//:ptth
		$a_81_1 = {73 61 64 73 61 64 73 61 64 73 61 64 73 61 } //01 00  sadsadsadsadsa
		$a_81_2 = {66 64 67 66 64 65 77 65 77 } //01 00  fdgfdewew
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}