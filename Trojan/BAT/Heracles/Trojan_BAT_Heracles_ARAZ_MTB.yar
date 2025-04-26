
rule Trojan_BAT_Heracles_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 04 11 04 0d 09 17 59 17 36 12 2b 00 09 19 2e 02 2b 14 07 19 } //2
		$a_03_1 = {16 0b 2b 10 00 04 06 07 91 6f ?? ?? ?? 0a 00 00 07 17 58 0b 07 03 fe 04 0c 08 2d e8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}