
rule Trojan_BAT_CryptInject_YR_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.YR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 02 7b 04 00 00 04 8e 69 5d 0c 06 07 03 07 91 02 7b 04 00 00 04 08 91 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}