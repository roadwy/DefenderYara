
rule TrojanDownloader_BAT_AveMariaRAT_V_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 0f 6f ?? 00 00 0a 13 10 12 0f 28 ?? 00 00 0a 28 ?? 00 00 0a 13 11 11 0a 11 10 11 11 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}