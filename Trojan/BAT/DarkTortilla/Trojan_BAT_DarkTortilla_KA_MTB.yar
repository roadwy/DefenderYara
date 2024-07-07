
rule Trojan_BAT_DarkTortilla_KA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 1f 64 da 13 06 00 11 06 1f 64 fe 02 13 09 11 09 2d ec } //10
		$a_01_1 = {4d 76 65 6b 66 6d 6c 73 66 6c 6c 73 64 76 6c } //1 Mvekfmlsfllsdvl
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}