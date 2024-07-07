
rule Trojan_Win32_Emotetcrypt_JF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 90 01 01 8b 55 08 03 55 fc 0f b6 0a 8b 45 fc 33 d2 f7 75 18 8b 45 14 0f b6 14 10 33 ca 8b 45 0c 03 45 fc 88 08 eb 90 00 } //1
		$a_01_1 = {66 6c 69 63 6b 72 } //1 flickr
		$a_01_2 = {56 67 37 4d 2b 4a 4a 62 30 44 35 4f 44 38 45 28 54 6f 3c 28 42 25 23 33 55 39 4a 44 69 65 6a 7a 59 3e 54 6f 4e 55 65 68 44 } //2 Vg7M+JJb0D5OD8E(To<(B%#3U9JDiejzY>ToNUehD
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*10) >=12
 
}