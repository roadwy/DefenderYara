
rule Trojan_BAT_DarkTortilla_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 19 5d 16 fe 01 13 06 11 06 2c 58 06 } //2
		$a_01_1 = {07 17 d6 0b 11 05 15 d6 13 05 11 05 16 3c 87 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}