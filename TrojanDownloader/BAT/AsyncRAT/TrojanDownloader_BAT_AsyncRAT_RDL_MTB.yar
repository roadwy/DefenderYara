
rule TrojanDownloader_BAT_AsyncRAT_RDL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 91 20 54 02 00 00 59 d2 9c 00 06 17 58 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}