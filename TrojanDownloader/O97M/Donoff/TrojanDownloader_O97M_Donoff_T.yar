
rule TrojanDownloader_O97M_Donoff_T{
	meta:
		description = "TrojanDownloader:O97M/Donoff.T,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 28 6f 62 78 76 68 4b 44 6b 4c 4c 39 35 29 } //1 .exec(obxvhKDkLL95)
		$a_01_1 = {55 6e 73 63 72 61 6d 62 6c 65 53 74 72 69 6e 67 28 22 6d 70 74 22 29 } //1 UnscrambleString("mpt")
		$a_01_2 = {7a 42 7a 62 6d 4d 6d 41 47 28 30 2c 20 6f 7a 38 77 4a 48 49 65 53 78 38 6c 2c 20 6f 62 78 76 68 4b 44 6b 4c 4c 39 35 2c 20 30 2c 20 30 29 } //1 zBzbmMmAG(0, oz8wJHIeSx8l, obxvhKDkLL95, 0, 0)
		$a_01_3 = {22 65 73 77 2e 73 74 69 6c 68 70 6c 63 72 22 } //1 "esw.stilhplcr"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}