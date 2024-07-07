
rule TrojanDownloader_Win64_IcedID_ZV{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZV,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8d 81 59 2e 00 00 d1 c8 d1 c8 c1 c8 02 35 1d 15 00 00 c1 c0 02 d1 c0 c3 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100) >=101
 
}