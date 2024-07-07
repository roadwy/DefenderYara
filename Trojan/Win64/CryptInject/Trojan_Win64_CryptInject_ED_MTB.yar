
rule Trojan_Win64_CryptInject_ED_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 8b f7 33 03 25 90 01 04 41 31 45 90 01 01 0f b6 43 90 01 01 41 08 45 90 01 01 eb 90 00 } //1
		$a_03_1 = {41 8d 80 20 90 01 03 48 83 c1 90 01 01 33 41 90 01 01 41 89 44 09 90 01 01 44 8b 87 90 01 04 41 8d 80 90 01 04 31 41 90 01 01 48 ff ca 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}