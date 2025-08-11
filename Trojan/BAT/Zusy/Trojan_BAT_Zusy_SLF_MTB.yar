
rule Trojan_BAT_Zusy_SLF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 7c 00 00 0a 13 05 11 04 28 7d 00 00 0a 13 06 16 13 07 2b 34 11 06 11 07 9a 25 28 45 00 00 0a 28 46 00 00 0a 13 08 28 7e 00 00 0a 11 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}