
rule TrojanDownloader_BAT_XWormRAT_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/XWormRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 00 65 00 7a 00 6b 00 67 00 75 00 6d 00 71 00 65 00 63 00 77 00 65 00 75 00 73 00 6e 00 6c 00 66 00 71 00 74 00 71 00 67 00 6f 00 73 00 2e 00 53 00 62 00 6b 00 6c 00 70 00 7a 00 78 00 68 00 72 00 76 00 70 00 6f 00 69 00 71 00 72 00 71 00 77 00 68 00 72 00 6b 00 6e 00 6b 00 67 00 6b 00 } //2 Vezkgumqecweusnlfqtqgos.Sbklpzxhrvpoiqrqwhrknkgk
		$a_01_1 = {3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 } //2 ://cdn.discordapp.com/attachments/
		$a_01_2 = {51 00 73 00 70 00 6d 00 71 00 67 00 6a 00 6d 00 63 00 74 00 70 00 62 00 61 00 6a 00 74 00 6b 00 65 00 } //2 Qspmqgjmctpbajtke
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}