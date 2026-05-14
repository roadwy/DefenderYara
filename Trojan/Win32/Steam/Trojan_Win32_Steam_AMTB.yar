
rule Trojan_Win32_Steam_AMTB{
	meta:
		description = "Trojan:Win32/Steam!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6d 20 44 65 73 6b 74 6f 70 20 41 75 74 68 65 6e 74 69 63 61 74 6f 72 } //Steam Desktop Authenticator  1
		$a_80_1 = {35 32 37 32 35 39 38 33 35 31 3a 41 41 47 41 54 63 58 61 79 38 51 4b 76 4b 64 68 75 73 48 57 34 61 6a 39 74 41 31 75 5a 5a 53 61 64 39 77 } //5272598351:AAGATcXay8QKvKdhusHW4aj9tA1uZZSad9w  1
		$a_80_2 = {31 38 30 39 35 31 31 30 36 35 3a 41 41 47 61 43 6e 4f 34 78 58 64 62 6d 34 5a 79 48 77 35 37 4c 32 31 62 51 6b 4b 6a 75 57 47 5a 4e 52 45 } //1809511065:AAGaCnO4xXdbm4ZyHw57L21bQkKjuWGZNRE  1
		$a_80_3 = {68 75 67 7a 68 6f 27 73 20 62 69 67 20 62 72 61 69 6e } //hugzho's big brain  1
		$a_80_4 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //https://api.telegram.org/bot  1
		$a_80_5 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 3f 63 68 61 74 5f 69 64 3d } ///sendDocument?chat_id=  1
		$a_80_6 = {26 63 61 70 74 69 6f 6e 3d 4e 45 57 20 4d 41 46 69 4c 45 } //&caption=NEW MAFiLE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}