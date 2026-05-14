
rule Trojan_Win64_ACRStealer_NUA_MTB{
	meta:
		description = "Trojan:Win64/ACRStealer.NUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 48 0f 2a c0 0f 28 c8 f3 0f 59 4b 1c 0f 2f ca 72 0c f3 0f 5c ca 0f 2f ca } //1
		$a_01_1 = {f6 44 01 03 0f 74 0b 0f b6 44 01 03 83 e0 f0 4c 03 c8 4c 33 ca 49 8b c9 5b e9 f1 3a ff ff cc } //2
		$a_01_2 = {48 89 9c 24 b0 40 00 00 48 89 ac 24 b8 40 00 00 48 8b 05 0a 06 05 00 48 33 c4 48 89 84 24 60 40 00 00 4c 8b f2 48 8b d9 48 85 c9 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}