
rule Trojan_Win32_CryptInject_AQ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 01 00 00 00 33 f6 3b b5 3c ff ff ff 7f ?? 8b 57 0c 8b 4f 14 2b d1 89 5d e4 66 0f b6 0c 32 03 d6 8b d9 2b 4d e4 66 85 c9 7d 06 81 c1 00 01 00 00 88 0a 03 f0 eb } //1
		$a_03_1 = {b8 01 00 00 00 33 ff 3b bd 34 ff ff ff 7f ?? 8b 4e 0c 8b 56 14 2b ca 89 5d e4 8d 14 39 66 0f b6 0c 39 8b d9 2b 4d e4 66 85 c9 7d 06 81 c1 00 01 00 00 88 0a 03 f8 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}