
rule TrojanDownloader_BAT_Banload_O{
	meta:
		description = "TrojanDownloader:BAT/Banload.O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 [0-0a] 68 00 74 00 74 00 70 00 } //1
		$a_03_1 = {20 30 75 00 00 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0b 07 72 ?? ?? 00 70 06 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 de 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}