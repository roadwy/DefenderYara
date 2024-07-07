
rule Backdoor_Win32_Netwire_PA_MTB{
	meta:
		description = "Backdoor:Win32/Netwire.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0d 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } //SOFTWARE\NetWire  15
		$a_80_1 = {66 69 6c 65 6e 61 6d 65 73 2e 74 78 74 } //filenames.txt  1
		$a_80_2 = {48 6f 73 74 2e 65 78 65 } //Host.exe  1
		$a_80_3 = {68 6f 73 74 6e 61 6d 65 } //hostname  1
		$a_80_4 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //encrypted_key  1
		$a_80_5 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //encryptedUsername  1
		$a_80_6 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //encryptedPassword  1
		$a_80_7 = {25 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //%s\Google\Chrome\User Data\Default\Login Data  1
		$a_80_8 = {25 73 5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //%s\Chromium\User Data\Default\Login Data  1
		$a_80_9 = {25 73 5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //%s\Comodo\Dragon\User Data\Default\Login Data  1
		$a_80_10 = {25 73 5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //%s\Yandex\YandexBrowser\User Data\Default\Login Data  1
		$a_80_11 = {25 73 5c 42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //%s\BraveSoftware\Brave-Browser\User Data\Default\Login Data  1
		$a_80_12 = {25 73 5c 33 36 30 43 68 72 6f 6d 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //%s\360Chrome\Chrome\User Data\Default\Login Data  1
	condition:
		((#a_80_0  & 1)*15+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=25
 
}