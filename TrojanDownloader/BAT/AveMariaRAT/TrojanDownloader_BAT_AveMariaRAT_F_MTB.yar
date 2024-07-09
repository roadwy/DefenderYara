
rule TrojanDownloader_BAT_AveMariaRAT_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 59 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe ?? 0c 08 90 0a 7a 00 20 ?? ?? ?? 00 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 80 ?? 00 00 04 16 0b 2b ?? 00 7e ?? 00 00 04 07 7e ?? 00 00 04 07 91 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}