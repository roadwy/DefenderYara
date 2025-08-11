
rule Trojan_BAT_XWorm_GVC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 27 00 00 06 25 13 07 1c 5e } //2
		$a_01_1 = {28 27 00 00 06 25 0d 1b 5e } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}