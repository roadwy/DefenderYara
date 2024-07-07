
rule Ransom_Win32_Filecoder_DP_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 63 72 79 70 74 6f 70 70 38 30 30 5c 73 68 61 5f 73 69 6d 64 2e 63 70 70 } //1 \cryptopp800\sha_simd.cpp
		$a_81_1 = {53 61 6c 73 61 32 30 } //1 Salsa20
		$a_81_2 = {72 65 70 74 65 72 40 74 75 74 61 2e 69 6f } //1 repter@tuta.io
		$a_81_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_4 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}