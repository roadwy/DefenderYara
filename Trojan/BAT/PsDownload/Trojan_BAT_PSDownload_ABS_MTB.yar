
rule Trojan_BAT_PSDownload_ABS_MTB{
	meta:
		description = "Trojan:BAT/PSDownload.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 39 8e 69 19 2c 1d 17 59 2b 33 2b 1c 0b 2b f0 06 07 91 0d 06 07 06 08 91 9c 1b 2c f7 06 08 09 9c 07 17 58 0b 08 17 59 0c 16 2d d4 07 08 32 e0 06 2a 0a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}