
rule Trojan_Win64_Bazarcrypt_GW_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {10 00 00 44 8b 90 02 02 33 d2 ff 15 90 02 04 48 8b 90 02 02 44 8b 90 02 02 48 8d 90 02 06 48 8b 90 02 02 e8 90 02 04 8b 4d 90 02 02 89 4c 90 02 02 48 8d 90 02 02 48 89 90 02 04 48 89 90 02 04 45 33 90 02 02 33 d2 45 8d 90 02 02 48 8b 90 02 02 ff 15 90 02 04 85 c0 0f 84 90 02 04 ff d6 90 00 } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  1
		$a_80_3 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}