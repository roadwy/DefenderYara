
rule Trojan_Win64_CryptInject_SA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 49 03 dc 83 e0 90 01 01 8a 44 05 90 01 01 30 02 49 03 d4 4d 2b f4 75 90 00 } //1
		$a_03_1 = {0f b7 c0 4d 8d 49 90 01 01 41 33 c0 44 69 c0 90 01 04 41 8b c0 c1 e8 90 01 01 44 33 c0 41 0f b7 01 66 85 c0 75 90 01 01 41 81 f8 90 01 04 74 90 01 01 48 8b 09 48 3b ca 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}