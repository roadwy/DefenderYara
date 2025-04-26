
rule Ransom_MSIL_CryptLockr_PA_MTB{
	meta:
		description = "Ransom:MSIL/CryptLockr.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 32 00 2e 00 30 00 5f 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 } //1 CryptoLocker2.0_RANSOMWARE
		$a_01_1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2f 00 73 00 20 00 2f 00 74 00 20 00 30 00 } //1 shutdown /s /t 0
		$a_01_2 = {73 00 68 00 69 00 65 00 6c 00 64 00 5f 00 50 00 4e 00 47 00 31 00 32 00 37 00 35 00 } //1 shield_PNG1275
		$a_01_3 = {59 6f 75 72 20 64 61 74 61 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 75 6e 69 71 75 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 79 74 68 6d } //1 Your data is encrypted with a unique encryption algorythm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}