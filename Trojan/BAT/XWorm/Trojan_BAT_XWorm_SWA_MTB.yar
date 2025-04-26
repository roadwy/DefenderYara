
rule Trojan_BAT_XWorm_SWA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 74 10 00 00 01 6f 6e 00 00 0a 6f 6f 00 00 0a 6f 6a 00 00 0a 72 22 03 00 70 72 a4 01 00 70 6f 70 00 00 0a 28 6d 00 00 0a 39 2a 00 00 00 02 74 10 00 00 01 6f 6e 00 00 0a 6f 6f 00 00 0a 6f 6a 00 00 0a 72 22 03 00 70 72 a4 01 00 70 6f 70 00 00 0a 0a dd 6f 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}