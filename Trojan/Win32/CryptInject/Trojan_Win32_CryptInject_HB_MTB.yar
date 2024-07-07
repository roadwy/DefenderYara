
rule Trojan_Win32_CryptInject_HB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 63 c2 48 69 c0 90 01 04 48 c1 e8 20 89 c1 c1 f9 03 89 d0 c1 f8 1f 29 c1 89 c8 c1 e0 05 01 c8 89 d1 29 c1 48 8b 55 b8 8b 45 f8 48 98 48 01 d0 89 ca 88 10 83 45 f8 01 8b 45 f8 48 98 48 3b 45 d8 72 90 00 } //10
		$a_01_1 = {46 00 45 00 4b 00 2e 00 44 00 4c 00 4c 00 } //1 FEK.DLL
		$a_01_2 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}