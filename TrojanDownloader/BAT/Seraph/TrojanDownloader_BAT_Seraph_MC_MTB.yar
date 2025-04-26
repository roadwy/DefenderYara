
rule TrojanDownloader_BAT_Seraph_MC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 13 03 38 ?? ?? ?? ?? fe ?? ?? ?? 45 01 00 00 00 05 00 00 00 38 ?? ?? ?? 00 11 03 13 04 38 ?? ?? ?? 00 11 02 11 03 28 ?? ?? ?? 06 38 ?? ?? ?? 00 11 03 16 6a 28 ?? ?? ?? 06 20 00 00 00 00 7e ?? 00 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff dd 48 } //1
		$a_01_1 = {4c 6f 67 69 6e 49 64 65 6e 74 69 66 69 65 72 } //1 LoginIdentifier
		$a_01_2 = {46 6c 75 73 68 49 64 65 6e 74 69 66 69 65 72 } //1 FlushIdentifier
		$a_01_3 = {57 00 59 00 4a 00 31 00 36 00 4c 00 63 00 47 00 49 00 6a 00 } //1 WYJ16LcGIj
		$a_01_4 = {44 6f 59 6f 75 54 68 69 6e 67 } //1 DoYouThing
		$a_01_5 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 costura.costura.dll.compressed
		$a_01_6 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //1 DeflateStream
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}