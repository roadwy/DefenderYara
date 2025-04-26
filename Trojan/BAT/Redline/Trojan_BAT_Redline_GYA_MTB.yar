
rule Trojan_BAT_Redline_GYA_MTB{
	meta:
		description = "Trojan:BAT/Redline.GYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 66 d2 9c 02 06 8f 18 00 00 01 25 71 18 00 00 01 20 83 00 00 00 59 d2 81 18 00 00 01 02 06 8f 18 00 00 01 25 71 18 00 00 01 1f 25 58 d2 81 18 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}