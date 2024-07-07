
rule Trojan_Win64_Emotetcrypt_KV_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 01 b8 90 01 04 42 32 4c 0f 90 01 01 41 f7 e8 41 88 49 90 01 01 c1 fa 90 01 01 8b cb 8b c2 83 c3 90 01 01 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 8b 05 90 01 04 83 c1 90 01 01 48 63 c9 0f b6 0c 01 42 32 4c 0e 90 01 01 41 88 49 90 01 01 49 ff ca 74 90 00 } //1
		$a_03_1 = {48 8d 7f 01 f7 eb c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c3 ff c3 6b d2 90 01 01 2b c2 48 63 c8 48 8b 05 90 01 04 0f b6 0c 01 41 32 4c 3e ff 88 4f ff 48 ff ce 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}