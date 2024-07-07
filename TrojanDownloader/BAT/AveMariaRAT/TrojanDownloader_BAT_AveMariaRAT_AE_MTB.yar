
rule TrojanDownloader_BAT_AveMariaRAT_AE_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 08 91 20 90 01 04 59 d2 9c 08 17 58 0c 08 06 8e 69 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}