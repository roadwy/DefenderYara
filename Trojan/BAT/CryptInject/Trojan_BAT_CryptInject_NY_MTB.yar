
rule Trojan_BAT_CryptInject_NY_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 20 00 01 00 00 6f ?? ?? ?? 0a 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 11 04 2a } //1
		$a_01_1 = {3f b6 1f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 } //1
		$a_01_2 = {34 62 65 65 2d 61 35 32 36 2d 31 38 65 30 36 65 30 37 64 65 32 36 } //1 4bee-a526-18e06e07de26
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}