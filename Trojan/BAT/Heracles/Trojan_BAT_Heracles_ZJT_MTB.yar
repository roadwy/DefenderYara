
rule Trojan_BAT_Heracles_ZJT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 8f 27 00 00 01 25 47 03 07 03 8e 69 5d 91 61 d2 52 16 0c 2b 1a 00 02 07 02 07 91 03 08 91 06 1f 1f 5f 62 08 61 07 58 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d dc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}