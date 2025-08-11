
rule Trojan_BAT_Mardom_ST_MTB{
	meta:
		description = "Trojan:BAT/Mardom.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 01 00 00 0a 25 6f 02 00 00 0a 72 ad 00 00 70 72 c3 00 00 70 6f 03 00 00 0a 72 ba 01 00 70 6f 04 00 00 0a 13 03 20 00 00 00 00 7e 3e 03 00 04 7b 28 03 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 01 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}