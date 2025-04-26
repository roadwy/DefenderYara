
rule TrojanDownloader_BAT_AveMariaRAT_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 09 6f ?? 00 00 0a 80 ?? 00 00 04 16 13 ?? 2b ?? 00 7e ?? 00 00 04 11 ?? 7e ?? 00 00 04 11 04 91 20 ?? 02 00 00 59 d2 9c 00 11 ?? 17 58 13 ?? 11 ?? 7e ?? 00 00 04 8e 69 fe ?? 13 ?? 11 ?? 2d 90 0a 67 00 72 ?? 00 00 70 28 ?? 00 00 0a 0a 06 6f ?? 00 00 0a 0b 07 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 09 6f } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}