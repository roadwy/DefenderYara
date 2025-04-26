
rule TrojanDownloader_BAT_NanoBot_PKZM_MTB{
	meta:
		description = "TrojanDownloader:BAT/NanoBot.PKZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 0f 72 4d 00 00 70 2b 0f 2b 14 2b 19 2b 1e de 22 73 13 00 00 0a 2b ea 73 14 00 00 0a 2b ea 28 ?? 00 00 0a 2b e5 6f ?? 00 00 0a 2b e0 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}