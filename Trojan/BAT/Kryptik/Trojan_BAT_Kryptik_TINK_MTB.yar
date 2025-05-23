
rule Trojan_BAT_Kryptik_TINK_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TINK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 65 30 65 63 63 36 65 30 2d 37 36 61 37 2d 34 34 31 35 2d 39 63 35 61 2d 35 39 33 31 34 34 37 62 39 39 63 39 } //10 $e0ecc6e0-76a7-4415-9c5a-5931447b99c9
		$a_01_1 = {43 46 30 30 31 32 33 31 } //1 CF001231
		$a_01_2 = {43 46 32 33 34 30 35 32 } //1 CF234052
		$a_01_3 = {43 46 33 32 31 34 38 31 32 33 } //1 CF32148123
		$a_01_4 = {43 46 33 34 32 34 32 33 35 36 36 35 } //1 CF3424235665
		$a_01_5 = {76 61 6c 69 64 61 74 65 4c 6f 67 69 6e } //1 validateLogin
		$a_01_6 = {69 73 47 75 65 73 74 } //1 isGuest
		$a_01_7 = {63 72 65 61 74 65 54 6f 6b 65 6e 41 75 74 68 } //1 createTokenAuth
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}