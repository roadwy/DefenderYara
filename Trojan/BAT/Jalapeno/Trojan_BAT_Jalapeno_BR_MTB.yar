
rule Trojan_BAT_Jalapeno_BR_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 7d f4 02 00 04 20 22 00 00 00 38 ae fd ff ff 7e ed 02 00 04 20 5d 2e 59 4f 20 ec f0 a8 3c 61 20 d1 6b 59 d4 59 20 e0 72 98 9f 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}