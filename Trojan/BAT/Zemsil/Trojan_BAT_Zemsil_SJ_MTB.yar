
rule Trojan_BAT_Zemsil_SJ_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 06 11 07 8e 69 5d 91 13 0b 07 06 91 11 0b 61 13 0c 06 17 58 09 5d 13 0d 07 11 0d 91 13 0e 16 13 05 2b 55 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}