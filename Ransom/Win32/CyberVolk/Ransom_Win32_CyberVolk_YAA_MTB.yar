
rule Ransom_Win32_CyberVolk_YAA_MTB{
	meta:
		description = "Ransom:Win32/CyberVolk.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 50 6f 6c 61 72 69 7a 65 64 5c 72 61 6e 73 6f 6d 5c 72 61 6e 73 6f 6d 5c 43 72 79 70 74 6f 5c 52 53 41 } //1 XPolarized\ransom\ransom\Crypto\RSA
		$a_01_1 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_2 = {53 00 74 00 61 00 72 00 74 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 Start Decryption
		$a_01_3 = {43 00 79 00 62 00 65 00 72 00 56 00 6f 00 6c 00 6b 00 5f 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 CyberVolk_ReadMe.txt
		$a_01_4 = {43 00 79 00 62 00 33 00 72 00 20 00 42 00 79 00 74 00 65 00 73 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 Cyb3r Bytes Ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}