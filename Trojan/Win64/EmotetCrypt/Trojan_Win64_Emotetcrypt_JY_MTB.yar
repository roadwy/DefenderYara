
rule Trojan_Win64_Emotetcrypt_JY_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af d1 48 63 d2 4c 89 c1 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 4c 8d 04 11 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 48 63 d2 49 01 d0 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 48 63 d2 4c 89 c1 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 01 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 01 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 60 7b 01 00 48 63 d2 48 29 d1 48 89 ca 48 39 d0 0f 82 } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}