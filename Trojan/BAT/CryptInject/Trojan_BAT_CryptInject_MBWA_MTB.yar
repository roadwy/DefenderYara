
rule Trojan_BAT_CryptInject_MBWA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? 00 00 0a 59 0b } //2
		$a_01_1 = {32 31 35 34 61 34 65 65 61 33 66 66 } //1 2154a4eea3ff
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}