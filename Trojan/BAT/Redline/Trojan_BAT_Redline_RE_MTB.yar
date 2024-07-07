
rule Trojan_BAT_Redline_RE_MTB{
	meta:
		description = "Trojan:BAT/Redline.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 56 50 4e } //1 OpenVPN
		$a_01_1 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 5f 49 4e 46 4f } //1 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
		$a_01_2 = {43 68 72 6f 6d 65 47 65 74 52 6f 61 6d 69 6e 67 4e 61 6d 65 } //1 ChromeGetRoamingName
		$a_01_3 = {73 64 66 39 33 34 61 73 64 } //2 sdf934asd
		$a_01_4 = {61 73 64 6b 39 33 34 35 61 73 64 } //2 asdk9345asd
		$a_01_5 = {61 64 6b 61 73 64 38 75 33 68 62 61 73 64 } //2 adkasd8u3hbasd
		$a_01_6 = {6b 6b 64 68 66 61 6b 64 61 73 64 } //2 kkdhfakdasd
		$a_01_7 = {5d 6f 37 00 00 0a 61 0c 06 72 63 08 00 70 08 28 a4 00 00 0a 6f a5 00 00 0a } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*3) >=14
 
}