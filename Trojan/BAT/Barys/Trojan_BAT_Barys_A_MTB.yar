
rule Trojan_BAT_Barys_A_MTB{
	meta:
		description = "Trojan:BAT/Barys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 0a 00 fe 0c 18 00 20 2d 31 7e 18 5a 20 6a c8 b2 df 61 38 61 ef ff ff 20 c1 fc fb 36 20 03 00 00 00 20 c4 2d 00 00 5a 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}