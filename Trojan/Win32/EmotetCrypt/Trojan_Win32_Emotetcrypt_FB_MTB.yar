
rule Trojan_Win32_Emotetcrypt_FB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b ca 03 0d ?? ?? ?? ?? 8b 45 d4 03 c8 8b 55 d8 2b ca 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 45 dc 2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 45 e8 88 04 0a } //1
		$a_81_1 = {62 49 53 21 62 21 55 33 34 31 4d 78 56 29 51 75 36 35 78 5e 45 51 71 26 57 34 35 30 35 4c 29 6d 65 38 61 72 6a 6e 35 65 23 4c 30 62 79 5e 56 21 21 58 3f 32 4a 79 71 6d 50 67 40 } //1 bIS!b!U341MxV)Qu65x^EQq&W4505L)me8arjn5e#L0by^V!!X?2JyqmPg@
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}