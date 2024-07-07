
rule Trojan_Win64_CryptInject_AB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 45 fd 99 35 90 01 04 66 a3 90 01 04 0f bf 45 f4 0f bf 0d 90 01 04 33 c1 a3 90 01 04 0f be 15 90 01 04 85 d2 74 90 00 } //1
		$a_03_1 = {66 89 55 f0 b8 90 01 04 66 89 45 f0 0f bf 0d 90 01 04 0f be 15 90 01 04 03 ca 0f bf 05 90 01 04 03 c1 66 a3 90 01 04 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}