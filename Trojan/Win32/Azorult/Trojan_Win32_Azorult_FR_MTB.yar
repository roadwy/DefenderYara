
rule Trojan_Win32_Azorult_FR_MTB{
	meta:
		description = "Trojan:Win32/Azorult.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 54 32 33 34 4c 4d 55 56 35 36 43 6b 6c 41 6f 70 71 37 38 42 72 73 74 75 76 77 78 79 7a 30 31 4e 4f 50 51 52 6d 47 48 49 4a 4b 57 58 59 5a 61 62 63 64 65 66 67 44 45 46 68 69 6a 6e 39 2b 2f } //ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/  1
		$a_80_1 = {53 59 53 49 6e 66 6f 2e 74 78 74 } //SYSInfo.txt  1
		$a_80_2 = {43 6f 6f 6b 69 65 4c 69 73 74 2e 74 78 74 } //CookieList.txt  1
		$a_80_3 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //Passwords.txt  1
		$a_00_4 = {85 c0 74 40 85 d2 74 31 53 56 57 89 c6 89 d7 8b 4f fc 57 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}