
rule Trojan_Win32_EmotetCrypt_KMG_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 8b 44 24 90 01 01 30 54 28 90 01 01 3b 6c 24 90 01 01 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 da 8b 54 24 90 01 01 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 2b 03 00 00 f7 fe 0f b6 f2 8d 04 2e e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 da 8b 54 24 90 01 01 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 9c 01 00 00 f7 fe 0f b6 f2 8d 04 2e e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 01 05 83 05 90 01 05 a1 90 01 04 3b 05 90 01 04 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 bf 24 01 00 00 f7 ff 0f b6 c2 8a 0c 08 8b 45 90 01 01 30 08 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 bf 9d 02 00 00 f7 ff 0f b6 c2 8a 0c 08 8b 45 90 01 01 30 08 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 bf 77 02 00 00 f7 ff 8a 04 0e 0f b6 fa 8a 14 37 8d 2c 37 88 14 0e 88 45 00 8d 43 90 01 01 99 f7 7c 24 90 01 01 41 81 f9 77 02 00 00 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 fa 0f b6 97 90 01 04 8d 0c 06 0f b6 01 03 d3 03 c2 99 8b dd f7 fb 0f b6 da 8d 04 33 e8 90 00 } //1
		$a_02_1 = {0f b6 da 0f b6 93 90 01 04 8d 0c 2f 03 d6 03 c2 99 be 95 02 00 00 f7 fe 0f b6 f2 8d 04 2e e8 90 00 } //1
		$a_02_2 = {0f b6 da 0f b6 93 90 01 04 8d 0c 2f 03 d6 03 c2 99 be c4 01 00 00 f7 fe 0f b6 f2 8d 04 2e e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}