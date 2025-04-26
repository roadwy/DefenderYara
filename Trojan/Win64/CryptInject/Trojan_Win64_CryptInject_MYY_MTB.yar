
rule Trojan_Win64_CryptInject_MYY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b7 0c 46 4d 8d 04 46 48 8b 05 ?? ?? 08 00 48 f7 f1 66 41 89 00 48 ff 0d ?? ?? 08 00 8a 0c 25 bf 4e 00 00 2a 0d ?? ?? 08 00 2a 0d 3e 4b 08 00 49 8b 03 41 32 cc 41 88 0c 01 48 ff 05 ?? ?? 08 00 0f b6 0b 41 8b 82 2c 71 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CryptInject_MYY_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.MYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 41 02 cb 40 02 cf 0f b6 d1 41 0f b6 44 95 08 41 30 46 ff 41 8b 44 95 ?? 41 31 44 9d ?? 41 8b 44 ad 08 40 fe c5 41 8d 0c 00 } //1
		$a_03_1 = {0f b6 c8 41 02 cb 40 02 cf 0f b6 d1 41 0f b6 44 95 08 41 30 46 fe 41 8b 44 95 ?? 41 31 44 9d ?? 41 8b 44 ad 08 41 8d 0c 00 43 31 4c 95 08 49 ff cf 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}