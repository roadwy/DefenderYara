
rule Trojan_BAT_DarkCloud_EABE_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.EABE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 07 00 00 0a 6f 08 00 00 0a 6f 09 00 00 0a 0c 73 0a 00 00 0a 0d 08 09 6f 0b 00 00 0a 09 6f 0c 00 00 0a 0a de 14 09 2c 06 09 6f 0d 00 00 0a dc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}