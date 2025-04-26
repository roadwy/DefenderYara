
rule Trojan_Win64_Emotetcrypt_KB_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 c7 48 8b c6 49 f7 e0 49 8b c8 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 05 48 6b c1 35 4c 2b c0 41 0f b6 04 18 43 32 04 0a 41 88 01 ff c7 4d 8d 49 01 81 ff 9d 0b 00 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}