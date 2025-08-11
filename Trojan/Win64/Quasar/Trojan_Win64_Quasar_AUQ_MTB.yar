
rule Trojan_Win64_Quasar_AUQ_MTB{
	meta:
		description = "Trojan:Win64/Quasar.AUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 4d 10 48 89 55 18 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 eb ?? 8b 4d f8 48 63 c1 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 48 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 89 d0 0f af 45 f8 01 45 fc 83 45 f8 01 } //3
		$a_03_1 = {48 8b 85 e8 ?? ?? ?? 48 8d 15 b0 82 00 00 48 89 c1 48 8b 05 31 d5 00 00 ff d0 48 89 85 e0 ?? ?? ?? 48 8b 85 e8 ?? ?? ?? 48 8d 15 9e 82 00 00 48 89 c1 48 8b 05 10 d5 00 00 ff d0 48 89 85 d8 ?? ?? ?? 48 8b 85 e8 ?? ?? ?? 48 8d 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}