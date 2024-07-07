
rule Trojan_Win32_Tarcloin_G{
	meta:
		description = "Trojan:Win32/Tarcloin.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c 98 8a 4c 24 18 c0 e1 04 02 4c 24 1c 32 4c 24 17 88 4c 24 20 33 c0 8a 44 24 20 04 14 34 5a c0 c8 04 } //2
		$a_01_1 = {3c 77 61 6c 6c 65 74 3e 00 } //1
		$a_01_2 = {6c 69 62 63 75 72 6c 2e 64 74 61 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}