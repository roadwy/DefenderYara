
rule Trojan_BAT_CryptInject_MBZ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 00 63 00 59 00 72 00 4a 00 79 00 41 00 79 00 50 00 66 00 } //2 bcYrJyAyPf
		$a_01_1 = {65 35 37 39 62 61 65 66 61 65 35 38 } //1 e579baefae58
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}