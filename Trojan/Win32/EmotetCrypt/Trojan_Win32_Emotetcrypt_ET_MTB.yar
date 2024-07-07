
rule Trojan_Win32_Emotetcrypt_ET_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 2b f2 03 35 90 01 04 2b 35 90 01 04 03 35 90 01 04 2b 35 90 01 04 2b 35 90 01 04 8b 45 dc 03 f0 8b 4d e0 03 f1 8b 55 e4 2b f2 03 35 90 01 04 03 35 90 01 04 2b 35 90 01 04 2b 35 90 01 04 03 35 90 01 04 03 35 90 01 04 8b 45 0c 8b 4d e8 88 0c 30 e9 90 00 } //1
		$a_81_1 = {46 6f 76 38 4f 43 57 6b 26 5a 21 6f 43 30 49 70 66 4a 53 6c 3f 25 24 6b 5e 74 39 25 5e 6d 48 64 6f 2a 6a 79 25 59 3f 35 62 3e 51 50 73 3c 58 4a 62 54 44 } //1 Fov8OCWk&Z!oC0IpfJSl?%$k^t9%^mHdo*jy%Y?5b>QPs<XJbTD
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}