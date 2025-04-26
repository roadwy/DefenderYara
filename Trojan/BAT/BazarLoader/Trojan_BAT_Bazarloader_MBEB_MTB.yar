
rule Trojan_BAT_Bazarloader_MBEB_MTB{
	meta:
		description = "Trojan:BAT/Bazarloader.MBEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0f 5d 13 16 11 07 11 0f 5b 13 17 11 0e 11 16 11 17 6f ?? 00 00 0a 13 34 11 11 11 10 12 34 28 ?? 00 00 0a 9c 11 10 17 58 13 10 11 07 17 58 13 07 11 07 11 0f 11 13 5a fe 04 13 18 11 18 2d be } //1
		$a_01_1 = {13 12 20 01 e8 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}