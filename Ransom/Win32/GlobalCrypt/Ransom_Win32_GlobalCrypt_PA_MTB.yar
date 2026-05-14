
rule Ransom_Win32_GlobalCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/GlobalCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 39 00 55 00 76 00 4b 00 34 00 58 00 } //1 .9UvK4X
		$a_01_1 = {66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 } //1 files encrypted
		$a_01_2 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 63 00 68 00 61 00 74 00 2f 00 } //1 .onion/chat/
		$a_03_3 = {31 d2 8d 44 24 ?? c7 44 24 54 ?? ?? ?? ?? c7 44 24 58 ?? ?? ?? ?? 66 89 54 24 ?? 8d 54 24 ?? 81 30 5a 00 5a 00 83 c0 04 39 d0 75 ?? 31 c0 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*4) >=7
 
}