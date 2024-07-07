
rule TrojanDownloader_Win64_Stealer_WQ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Stealer.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c9 33 d2 0f b6 04 2a 49 83 c0 01 83 c1 01 41 30 40 ff 48 83 c2 01 49 83 e9 01 } //2
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 62 69 6e } //1 payload.bin
		$a_81_2 = {6a 65 72 72 79 2e 6a 70 67 } //1 jerry.jpg
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}