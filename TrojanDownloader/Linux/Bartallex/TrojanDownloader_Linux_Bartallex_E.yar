
rule TrojanDownloader_Linux_Bartallex_E{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.E,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 50 54 54 48 4c 4d 58 2e 32 4c 4d 58 53 4d 22 29 29 } //1 CreateObject(StrReverse("PTTHLMX.2LMXSM"))
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 28 22 64 61 6f 6c 6e 77 6f 64 2f 6d 6f 63 2e } //1 StrReverse("daolnwod/moc.
		$a_01_2 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 22 70 2f 2f 3a 70 22 29 20 2b 20 } //1 + StrReverse("p//:p") + 
		$a_03_3 = {53 74 72 52 65 76 65 72 73 65 28 22 90 02 0a 3d 69 3f 70 68 70 2e 22 29 90 00 } //1
		$a_01_4 = {2e 4f 70 65 6e 28 53 74 72 52 65 76 65 72 73 65 28 22 54 53 4f 50 22 29 2c } //1 .Open(StrReverse("TSOP"),
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}