
rule Trojan_Win64_CryptInject_PAEA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.PAEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 6d 65 6d 6f 72 79 } //1 xmemory
		$a_01_1 = {43 61 6e 74 20 42 79 70 61 73 73 20 52 2e 41 2e 43 20 48 6f 6f 6b } //1 Cant Bypass R.A.C Hook
		$a_01_2 = {4f 79 75 6e 61 20 45 6e 6a 65 6b 74 65 20 45 64 69 6c 65 6d 65 64 69 } //1 Oyuna Enjekte Edilemedi
		$a_01_3 = {43 72 49 6e 6a 65 63 74 6f 72 63 2b 2b } //1 CrInjectorc++
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}