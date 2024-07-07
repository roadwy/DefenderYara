
rule Trojan_BAT_Netwire_CR_MTB{
	meta:
		description = "Trojan:BAT/Netwire.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 61 d2 9c 11 05 17 58 16 2d 04 13 05 11 05 06 8e 69 32 dd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}