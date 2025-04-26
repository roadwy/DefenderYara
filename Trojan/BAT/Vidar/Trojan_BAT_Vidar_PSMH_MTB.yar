
rule Trojan_BAT_Vidar_PSMH_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 6f 09 01 00 0a 11 06 6f 97 00 00 0a 16 73 c9 00 00 0a 13 0d 11 0d 11 07 28 59 03 00 06 de 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}