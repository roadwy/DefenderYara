
rule Trojan_BAT_Phemedrone_APM_MTB{
	meta:
		description = "Trojan:BAT/Phemedrone.APM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 07 11 08 08 11 07 91 58 20 00 01 00 00 5d 13 08 08 11 07 91 0d 08 11 07 08 11 08 91 9c 08 11 08 09 9c 08 08 11 07 91 08 11 08 91 58 20 00 01 00 00 5d 91 13 0a 07 11 09 02 11 09 91 11 0a 61 d2 9c 11 09 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}