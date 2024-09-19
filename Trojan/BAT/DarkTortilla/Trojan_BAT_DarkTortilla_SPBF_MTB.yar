
rule Trojan_BAT_DarkTortilla_SPBF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1d 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 4c 61 b4 9c 00 00 08 17 d6 0c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}