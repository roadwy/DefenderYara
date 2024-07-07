
rule Trojan_BAT_PsDownloader_CXA_MTB{
	meta:
		description = "Trojan:BAT/PsDownloader.CXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 00 28 02 00 00 2b 06 14 17 8d 90 01 04 25 90 00 } //5
		$a_03_1 = {28 1c 00 00 0a 7e 90 01 04 02 1a 58 08 6f 90 01 04 28 90 01 04 a5 90 01 04 0b 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}