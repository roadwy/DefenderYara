
rule TrojanDownloader_O97M_Donoff_BP{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BP,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 65 67 73 76 72 33 32 20 2f 73 20 2f 6e 20 2f 75 20 2f 69 3a 68 74 74 70 3a 2f 2f 90 02 2d 2e 73 63 74 20 73 63 72 6f 62 6a 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_BP_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BP,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 51 47 38 6a 67 47 63 70 31 55 4c 50 20 3d 20 77 68 70 59 36 6d 62 74 51 49 52 48 39 35 7a 20 2d 20 28 28 77 68 70 59 36 6d 62 74 51 49 52 48 39 35 7a 20 5c 20 66 43 4b 72 71 6d 29 20 2a 20 66 43 4b 72 71 6d 29 } //01 00  iQG8jgGcp1ULP = whpY6mbtQIRH95z - ((whpY6mbtQIRH95z \ fCKrqm) * fCKrqm)
		$a_00_1 = {52 71 4f 78 64 4a 36 61 28 48 4a 52 45 74 62 53 2c 20 28 4a 56 74 75 42 75 44 7a 64 36 6f 42 54 48 20 2a 20 4d 6a 6c 49 69 4c 6f 64 6a 73 61 7a 29 20 2b 20 77 4d 69 51 63 71 55 6c 50 66 6f 75 39 4e 66 29 } //01 00  RqOxdJ6a(HJREtbS, (JVtuBuDzd6oBTH * MjlIiLodjsaz) + wMiQcqUlPfou9Nf)
		$a_00_2 = {54 74 76 47 55 51 55 33 20 3d 20 28 4e 75 4e 64 48 45 76 68 70 77 63 20 2d 20 4d 6a 6c 49 69 4c 6f 64 6a 73 61 7a 29 20 2f 20 68 75 70 74 6c 49 53 4d 35 28 42 4e 4e 77 53 75 33 6f 6c 45 46 77 30 77 69 29 } //00 00  TtvGUQU3 = (NuNdHEvhpwc - MjlIiLodjsaz) / huptlISM5(BNNwSu3olEFw0wi)
	condition:
		any of ($a_*)
 
}