
rule TrojanDownloader_O97M_Powdow_BWK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BWK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 68 4b 77 20 2b 20 48 56 20 2b 20 62 68 68 7a 76 45 58 63 45 4b 69 20 2b 20 72 68 72 5a 73 57 79 4f 20 2b 20 52 45 73 6b 46 4d 45 6e 47 59 69 20 2b 20 5a 66 66 5a 46 44 44 4e 69 4b 20 2b 20 58 59 20 2b 20 6b 51 59 52 45 6e 43 69 54 73 42 20 2b 20 41 43 53 4a 45 61 42 4c 47 20 2b 20 63 4a 75 75 64 73 51 } //01 00  = hKw + HV + bhhzvEXcEKi + rhrZsWyO + REskFMEnGYi + ZffZFDDNiK + XY + kQYREnCiTsB + ACSJEaBLG + cJuudsQ
		$a_01_1 = {75 6b 2e 52 75 6e 20 4d 7a 51 44 4e 2c } //00 00  uk.Run MzQDN,
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BWK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BWK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 49 55 48 4c 51 66 54 48 47 54 45 20 2b 20 43 4a 50 54 20 2b 20 72 7a 58 63 55 20 2b 20 58 56 65 65 61 51 73 20 2b 20 52 4c 74 74 64 79 52 44 42 61 73 20 2b 20 4c 42 45 46 66 20 2b 20 70 6b 66 77 58 51 72 20 2b 20 47 69 4d 4e 69 42 53 4e 56 4d 73 20 2b 20 56 47 6e 4e 69 56 20 2b 20 68 48 20 2b } //01 00  = IUHLQfTHGTE + CJPT + rzXcU + XVeeaQs + RLttdyRDBas + LBEFf + pkfwXQr + GiMNiBSNVMs + VGnNiV + hH +
		$a_01_1 = {4a 4f 73 51 68 4d 68 4b 4c 2e 52 75 6e 20 4f 66 79 43 } //00 00  JOsQhMhKL.Run OfyC
	condition:
		any of ($a_*)
 
}