
rule Trojan_Win64_Emotetcrypt_KI_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 83 c4 01 41 f7 ed c1 fa 03 8b c2 c1 e8 1f 03 c2 49 63 d5 41 83 c5 01 48 98 48 8d 0c 40 48 8b 05 ?? ?? ?? ?? 48 c1 e1 04 48 03 c8 0f b6 04 0a 42 32 44 27 ff 48 83 ed 01 41 88 44 24 ff } //1
		$a_03_1 = {49 83 c4 01 41 f7 ed c1 fa 04 8b c2 c1 e8 1f 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 ca 49 63 d5 41 83 c5 01 48 6b c9 31 48 03 c8 0f b6 04 0a 42 32 44 27 ff 48 83 ed 01 41 88 44 24 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}