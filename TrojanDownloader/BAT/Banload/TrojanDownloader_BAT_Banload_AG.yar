
rule TrojanDownloader_BAT_Banload_AG{
	meta:
		description = "TrojanDownloader:BAT/Banload.AG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 64 61 6b 6c 00 6e 6f 6d 65 64 6f 7a 69 70 00 73 65 6e 68 61 64 6f 7a 69 70 00 6e 6f 6d 65 64 6f 65 78 65 00 } //1
		$a_03_1 = {74 00 6f 00 70 00 69 00 63 00 73 00 2e 00 7a 00 69 00 70 00 ?? ?? ?? ?? 64 00 66 00 67 00 78 00 2e 00 65 00 78 00 65 00 ?? ?? 72 00 75 00 6e 00 61 00 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}