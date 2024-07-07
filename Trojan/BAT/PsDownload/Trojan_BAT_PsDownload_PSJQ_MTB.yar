
rule Trojan_BAT_PsDownload_PSJQ_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.PSJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 16 00 00 00 00 06 09 02 03 09 58 91 05 61 d2 9c 00 09 17 58 0d 05 17 58 10 03 09 04 fe 04 13 04 7e 16 00 00 04 38 b6 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}