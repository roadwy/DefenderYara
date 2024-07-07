
rule Trojan_BAT_RedLine_RDBS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}