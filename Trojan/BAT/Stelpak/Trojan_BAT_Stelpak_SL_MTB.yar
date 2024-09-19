
rule Trojan_BAT_Stelpak_SL_MTB{
	meta:
		description = "Trojan:BAT/Stelpak.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 04 08 13 05 11 04 11 05 03 8e 69 5d } //2
		$a_01_1 = {07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}