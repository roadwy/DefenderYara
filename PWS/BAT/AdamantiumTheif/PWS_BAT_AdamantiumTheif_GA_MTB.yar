
rule PWS_BAT_AdamantiumTheif_GA_MTB{
	meta:
		description = "PWS:BAT/AdamantiumTheif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0a 00 00 "
		
	strings :
		$a_80_0 = {41 64 61 6d 61 6e 74 69 75 6d 2d 54 68 69 65 66 2f 6d 61 73 74 65 72 2f 53 74 65 61 6c 65 72 2f 53 74 65 61 6c 65 72 } //Adamantium-Thief/master/Stealer/Stealer  10
		$a_80_1 = {6c 69 62 73 6f 64 69 75 6d 2e 64 6c 6c } //libsodium.dll  1
		$a_80_2 = {62 72 6f 77 73 65 72 43 6f 6f 6b 69 65 73 } //browserCookies  1
		$a_80_3 = {4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 } //Opera Software\Opera Stable  1
		$a_80_4 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 } //Google\Chrome  1
		$a_80_5 = {59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 } //Yandex\YandexBrowser  1
		$a_80_6 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //encrypted_key  1
		$a_80_7 = {6f 73 5f 63 72 79 70 74 } //os_crypt  1
		$a_80_8 = {43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e } //Comodo\Dragon  1
		$a_80_9 = {4e 6f 74 20 63 6f 6e 6e 65 63 74 65 64 20 74 6f 20 69 6e 74 65 72 6e 65 74 21 } //Not connected to internet!  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=15
 
}