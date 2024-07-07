
rule TrojanDownloader_BAT_Pwsx_SO_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 9f 00 00 70 6f 16 00 00 0a 6f 17 00 00 0a 6f 18 00 00 0a 6f 19 00 00 0a 6f 1a 00 00 0a 0a dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}