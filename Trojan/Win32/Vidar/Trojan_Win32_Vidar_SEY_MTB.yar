
rule Trojan_Win32_Vidar_SEY_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 05 00 20 42 00 69 0c 24 00 03 00 00 01 c8 8d 0d 9c 36 42 00 6b 14 24 0c 01 d1 89 01 } //2
		$a_00_1 = {5c 5c 4d 6f 6e 65 72 6f 5c 5c 77 61 6c 6c 65 74 30 31 32 33 34 35 36 37 38 39 } //1 \\Monero\\wallet0123456789
		$a_00_2 = {5c 5c 42 72 61 76 65 57 61 6c 6c 65 74 5c 5c 50 } //1 \\BraveWallet\\P
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}