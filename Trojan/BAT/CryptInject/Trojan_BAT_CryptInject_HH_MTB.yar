
rule Trojan_BAT_CryptInject_HH_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.HH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 11 00 00 06 13 01 38 00 00 00 00 dd 2a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}