
rule Trojan_BAT_CobaltStrike_G_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8e 69 18 5b 07 58 91 02 07 91 61 d2 0c } //2
		$a_01_1 = {04 8e 69 b8 20 00 30 00 00 1f 40 28 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}