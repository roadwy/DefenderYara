
rule Trojan_BAT_Rhadamanthys_UDP_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.UDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0f 11 09 16 73 3e 00 00 0a 13 06 20 00 00 00 00 7e 7a 02 00 04 7b 7b 02 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}