
rule TrojanDownloader_BAT_Seraph_ABGH_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 73 16 ?? ?? 0a 0b 00 73 ?? ?? ?? 0a 0c 00 07 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0d 00 09 08 6f ?? ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 13 04 de 16 08 2c 07 08 6f ?? ?? ?? 0a 00 dc } //2
		$a_01_1 = {43 00 72 00 67 00 75 00 71 00 76 00 6e 00 76 00 7a 00 6b 00 71 00 69 00 65 00 77 00 78 00 77 00 62 00 61 00 65 00 63 00 72 00 } //1 Crguqvnvzkqiewxwbaecr
		$a_01_2 = {55 00 6a 00 6e 00 7a 00 75 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Ujnzu.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}