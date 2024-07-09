
rule Trojan_Win64_Emotetcrypt_JO_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 03 c1 48 63 0d ?? ?? ?? ?? 48 2b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 48 63 c9 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_2 = {30 64 68 38 43 38 77 21 65 62 23 23 3f 28 65 43 66 6b 68 74 53 73 34 74 71 39 3e 38 4e 6e 6b 45 51 4b 65 6e 40 7a } //1 0dh8C8w!eb##?(eCfkhtSs4tq9>8NnkEQKen@z
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}