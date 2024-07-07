
rule TrojanDownloader_Win32_PterodoGen_C_dha{
	meta:
		description = "TrojanDownloader:Win32/PterodoGen.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_41_0 = {b7 45 fc 8b 4d 08 0f be 0c 01 0f b7 45 fc 0f b7 55 18 03 c2 0f b7 75 14 99 f7 fe 8b 45 10 0f be 14 10 33 ca 0f b7 45 fc 8b 55 f8 88 0c 02 eb ba 01 } //1
		$a_8b_1 = {24 89 d1 31 d2 01 d8 f7 f6 8b 44 24 20 0f b6 04 10 89 ca 8b 4c 24 18 32 04 19 88 44 1d 00 0f b7 df 47 39 d3 72 d8 00 00 5d 04 00 00 45 00 05 80 5c 25 00 00 46 00 05 80 00 00 01 00 08 00 0f 00 ac } //10240
	condition:
		((#a_41_0  & 1)*1+(#a_8b_1  & 1)*10240) >=1
 
}