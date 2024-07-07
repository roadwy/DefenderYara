
rule Trojan_Win32_Zonsterarch_AF{
	meta:
		description = "Trojan:Win32/Zonsterarch.AF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 44 5f 43 4f 4f 4b 49 45 5f 55 52 4c 3d } //1 PROD_COOKIE_URL=
		$a_01_1 = {49 6e 74 65 72 6e 61 6c 41 75 74 6f 50 6f 70 75 70 4d 73 67 00 } //1
		$a_01_2 = {43 75 73 74 6f 6d 65 72 52 65 67 57 65 62 53 69 74 65 55 52 4c } //1 CustomerRegWebSiteURL
		$a_01_3 = {53 45 54 5f 50 41 59 50 41 47 45 5f 55 52 4c } //1 SET_PAYPAGE_URL
		$a_01_4 = {4c 4f 47 56 41 52 4e 41 4d 45 50 41 49 44 } //1 LOGVARNAMEPAID
		$a_01_5 = {61 63 74 69 6f 6e 3d 7b 41 43 54 49 4f 4e 5f 49 44 7d 26 } //1 action={ACTION_ID}&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}