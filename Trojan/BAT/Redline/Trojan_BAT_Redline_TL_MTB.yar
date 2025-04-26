
rule Trojan_BAT_Redline_TL_MTB{
	meta:
		description = "Trojan:BAT/Redline.TL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 12 00 00 0a 25 6f 13 00 00 0a 0b 06 20 94 3d 8d d7 28 01 00 00 06 0c 12 02 28 14 00 00 0a 74 01 00 00 1b 0d 20 89 c0 85 dd 2b 00 28 02 00 00 2b 09 6f 15 00 00 0a 09 16 09 8e 69 28 11 00 00 0a 12 02 28 16 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}