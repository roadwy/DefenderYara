
rule Trojan_BAT_Reline_BE_MTB{
	meta:
		description = "Trojan:BAT/Reline.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {54 72 79 49 6e 69 74 4e 6f 72 64 56 50 4e } //1 TryInitNordVPN
		$a_81_1 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 5f 49 4e 46 4f } //1 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
		$a_81_2 = {47 65 63 6b 6f 52 6f 61 6d 69 6e 67 4e 61 6d 65 } //1 GeckoRoamingName
		$a_81_3 = {43 68 72 6f 6d 65 47 65 74 52 6f 61 6d 69 6e 67 4e 61 6d 65 } //1 ChromeGetRoamingName
		$a_81_4 = {43 68 72 5f 30 5f 4d 5f 65 } //1 Chr_0_M_e
		$a_81_5 = {54 72 79 49 6e 69 74 44 69 73 63 6f 72 64 } //1 TryInitDiscord
		$a_81_6 = {64 76 73 6a 69 6f 68 71 33 } //1 dvsjiohq3
		$a_81_7 = {67 6b 64 73 69 38 79 32 33 34 } //1 gkdsi8y234
		$a_81_8 = {61 64 6b 61 73 64 38 75 33 68 62 61 73 64 } //1 adkasd8u3hbasd
		$a_81_9 = {6b 6b 64 68 66 61 6b 64 61 73 64 } //1 kkdhfakdasd
		$a_81_10 = {61 73 64 61 73 6f 64 39 32 33 34 6f 61 73 64 } //1 asdasod9234oasd
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}