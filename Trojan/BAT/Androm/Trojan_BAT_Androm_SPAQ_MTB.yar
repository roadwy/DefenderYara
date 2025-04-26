
rule Trojan_BAT_Androm_SPAQ_MTB{
	meta:
		description = "Trojan:BAT/Androm.SPAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}