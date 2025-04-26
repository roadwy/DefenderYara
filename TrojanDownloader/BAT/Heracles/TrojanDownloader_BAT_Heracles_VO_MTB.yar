
rule TrojanDownloader_BAT_Heracles_VO_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 07 6f ?? ?? ?? 0a 69 0d 09 8d 2a 00 00 01 0a 38 15 00 00 00 07 06 08 09 6f ?? ?? ?? 0a 13 04 08 11 04 58 0c 09 11 04 59 0d 09 16 3d e4 ff ff ff dd 0d 00 00 00 } //2
		$a_01_1 = {4e 45 58 55 53 2e 65 78 65 } //2 NEXUS.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}