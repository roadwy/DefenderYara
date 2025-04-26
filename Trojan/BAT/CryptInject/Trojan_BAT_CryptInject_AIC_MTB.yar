
rule Trojan_BAT_CryptInject_AIC_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.AIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 31 7e bc 01 00 04 06 7e bb 01 00 04 02 07 6f ?? ?? ?? 0a 7e ae 00 00 04 07 7e ae 00 00 04 8e 69 5d 91 61 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}