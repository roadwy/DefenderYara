
rule Ransom_Win32_Paradise_BD_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 16 00 0a 00 00 "
		
	strings :
		$a_80_0 = {2f 43 20 73 63 20 64 65 6c 65 74 65 20 56 53 53 41 } ///C sc delete VSSA  10
		$a_80_1 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 69 6e 20 42 69 74 63 6f 69 6e 73 2e } //You have to pay in Bitcoins.  10
		$a_03_2 = {52 45 41 44 4d 45 90 02 0a 68 74 6d 6c 90 00 } //5
		$a_80_3 = {43 79 63 6c 65 44 65 66 65 6e 64 65 72 } //CycleDefender  1
		$a_80_4 = {44 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 69 65 73 } //DeleteShadowCopies  1
		$a_80_5 = {43 72 79 70 74 65 64 50 72 69 76 61 74 65 4b 65 79 } //CryptedPrivateKey  1
		$a_80_6 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //System.Security.Cryptography  1
		$a_80_7 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //RSACryptoServiceProvider  1
		$a_80_8 = {3c 43 52 59 50 54 45 44 3e } //<CRYPTED>  1
		$a_80_9 = {3c 2f 43 52 59 50 54 45 44 3e } //</CRYPTED>  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_03_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=22
 
}