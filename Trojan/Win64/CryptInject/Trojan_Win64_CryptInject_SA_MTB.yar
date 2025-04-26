
rule Trojan_Win64_CryptInject_SA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 49 03 dc 83 e0 ?? 8a 44 05 ?? 30 02 49 03 d4 4d 2b f4 75 } //1
		$a_03_1 = {0f b7 c0 4d 8d 49 ?? 41 33 c0 44 69 c0 ?? ?? ?? ?? 41 8b c0 c1 e8 ?? 44 33 c0 41 0f b7 01 66 85 c0 75 ?? 41 81 f8 ?? ?? ?? ?? 74 ?? 48 8b 09 48 3b ca 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}