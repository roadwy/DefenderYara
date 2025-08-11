
rule TrojanDownloader_O97M_Donoff_SRH_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SRH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 22 68 74 74 70 3a 2f 2f 33 38 2e 31 38 30 2e 32 30 36 2e 36 31 2f 65 6e 67 69 6e 65 2e 70 68 70 22 } //2 Open "POST", "http://38.180.206.61/engine.php"
		$a_81_1 = {45 6e 76 69 72 6f 6e 28 22 43 4f 4d 50 55 54 45 52 4e 41 4d 45 22 29 } //1 Environ("COMPUTERNAME")
		$a_81_2 = {45 6e 76 69 72 6f 6e 28 22 55 73 65 72 6e 61 6d 65 22 29 } //1 Environ("Username")
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}