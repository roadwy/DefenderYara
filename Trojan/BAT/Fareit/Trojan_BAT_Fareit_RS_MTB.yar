
rule Trojan_BAT_Fareit_RS_MTB{
	meta:
		description = "Trojan:BAT/Fareit.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 91 8c 15 00 00 01 13 08 11 06 7e 16 00 00 04 8e b7 5d 8c 1a 00 00 01 13 07 07 11 06 11 08 7e 16 00 00 04 11 07 28 12 00 00 0a 91 8c 15 00 00 01 28 13 00 00 0a 28 14 00 00 0a 9c 11 06 17 58 13 06 11 06 11 09 31 b6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}