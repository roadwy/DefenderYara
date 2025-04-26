
rule Trojan_O97M_RevengeRAT_RDA_MTB{
	meta:
		description = "Trojan:O97M/RevengeRAT.RDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e 20 6e 75 6c 20 26 20 73 74 61 72 74 20 43 } //2 > nul & start C
		$a_01_1 = {6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 31 30 20 } //2 ng 127.0.0.1 -n 10 
		$a_01_2 = {61 2e 52 75 6e 20 28 4d 5f 53 20 2b 20 54 4f 47 41 43 44 54 20 2b 20 4d 5f 53 31 20 2b 20 4d 5f 53 32 20 2b 20 4d 5f 53 33 29 2c 20 30 } //2 a.Run (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}