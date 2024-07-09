
rule Trojan_BAT_PsDownloader_PSWL_MTB{
	meta:
		description = "Trojan:BAT/PsDownloader.PSWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 ac 03 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 0b 08 28 ?? 00 00 0a 2d 10 08 11 0b 28 ?? 00 00 0a 16 13 18 dd 1e 03 00 00 11 13 7b 2c 00 00 04 11 0b 6f ?? 00 00 0a 26 14 13 0c 72 cf 07 00 70 73 c0 00 00 0a 13 0d 11 07 13 0e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}