
rule Trojan_BAT_Androm_AMBF_MTB{
	meta:
		description = "Trojan:BAT/Androm.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 07 11 04 5d 13 08 11 07 1f 16 5d 13 09 11 07 17 58 11 04 5d 13 0a 07 11 08 91 13 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}