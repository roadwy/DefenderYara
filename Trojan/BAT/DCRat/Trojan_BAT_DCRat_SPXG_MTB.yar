
rule Trojan_BAT_DCRat_SPXG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SPXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 52 59 70 75 4f 4b 33 33 68 33 49 76 33 78 6d 66 6f 2e 54 42 43 38 58 55 35 41 4c 39 36 47 55 6f 38 68 74 77 } //1 YRYpuOK33h3Iv3xmfo.TBC8XU5AL96GUo8htw
		$a_01_1 = {6d 75 65 6c 39 6a 77 59 5a 5a 73 69 78 4c 4e 67 43 36 2e 32 78 6d 4f 64 53 67 41 45 48 38 75 31 52 4c 53 6e 66 } //1 muel9jwYZZsixLNgC6.2xmOdSgAEH8u1RLSnf
		$a_80_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //System.Security.Cryptography.AesCryptoServiceProvider  1
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_80_4 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //GetDelegateForFunctionPointer  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}