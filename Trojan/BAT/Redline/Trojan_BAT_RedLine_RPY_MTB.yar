
rule Trojan_BAT_RedLine_RPY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 87 00 00 0a 03 08 1f 09 58 1e 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}