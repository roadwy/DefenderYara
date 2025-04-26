
rule Trojan_BAT_DarkTortilla_F_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 05 60 04 66 05 66 60 5f } //2
		$a_01_1 = {02 03 5d 0b } //2 ̂ଢ଼
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}