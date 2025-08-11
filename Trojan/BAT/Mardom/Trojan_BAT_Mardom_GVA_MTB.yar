
rule Trojan_BAT_Mardom_GVA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 1b 00 00 0a 14 18 8d 01 00 00 01 25 16 02 a2 25 17 03 a2 6f 1c 00 00 0a 26 2a } //2
		$a_01_1 = {6f 16 00 00 0a 26 07 17 6f 17 00 00 0a 07 17 8d 17 00 00 01 25 16 06 a2 6f 18 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}