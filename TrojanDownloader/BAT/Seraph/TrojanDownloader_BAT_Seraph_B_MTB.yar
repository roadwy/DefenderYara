
rule TrojanDownloader_BAT_Seraph_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {16 0a 38 0e 00 00 00 20 e8 03 00 00 28 05 00 00 0a 06 17 58 0a 06 1f 16 3f ea ff ff ff 28 06 00 00 0a 14 fe 06 90 01 03 06 73 07 00 00 0a 6f 08 00 00 0a 73 90 01 03 06 25 14 fe 06 90 01 03 06 73 90 01 03 06 6f 90 01 03 06 6f 90 01 03 06 2a 90 00 } //1
		$a_02_1 = {0a 0b 06 07 6f 90 01 03 0a 07 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 0c dd 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}