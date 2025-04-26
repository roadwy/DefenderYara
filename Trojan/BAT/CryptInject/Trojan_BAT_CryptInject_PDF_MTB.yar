
rule Trojan_BAT_CryptInject_PDF_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 6f 00 00 06 26 11 06 1f 0b 93 20 6a 29 00 00 59 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}