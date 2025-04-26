
rule Trojan_BAT_Vidar_DF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 12 06 08 06 09 91 9c 06 09 11 12 9c 08 17 58 0c 08 20 00 01 00 00 32 d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}