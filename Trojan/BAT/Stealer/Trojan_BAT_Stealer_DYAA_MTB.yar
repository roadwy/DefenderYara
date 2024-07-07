
rule Trojan_BAT_Stealer_DYAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.DYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 0d 06 08 02 08 91 07 61 d2 9c 08 17 58 0c 08 02 8e 69 32 ed } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}