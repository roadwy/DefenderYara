
rule Trojan_BAT_CryptInject_MBEN_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d 35 00 35 00 46 00 55 00 34 00 36 00 34 00 56 00 48 00 55 00 34 00 38 00 42 00 42 00 55 00 38 00 43 00 53 00 43 00 34 00 48 00 35 00 00 05 68 00 68 00 00 05 67 00 67 00 00 09 4c 00 6f 00 61 00 64 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}