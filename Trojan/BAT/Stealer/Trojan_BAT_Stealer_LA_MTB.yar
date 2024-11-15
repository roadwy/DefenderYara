
rule Trojan_BAT_Stealer_LA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 07 08 91 06 08 06 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 00 08 17 58 0c 08 07 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Stealer_LA_MTB_2{
	meta:
		description = "Trojan:BAT/Stealer.LA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //2 \Yandex\YandexBrowser\User Data\Default\Cookies
		$a_01_1 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //2 \Google\Chrome\User Data\Default\Login Data
		$a_01_2 = {5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 74 00 61 00 62 00 6c 00 65 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //2 \Opera Software\Opera Stable\Login Data
		$a_01_3 = {5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //2 \Yandex\YandexBrowser\User Data\Default\Login Data
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}