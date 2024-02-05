
rule Trojan_Win32_CrypterX_DSK_MTB{
	meta:
		description = "Trojan:Win32/CrypterX.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 54 6e 2a 45 31 72 4a 5a 63 64 43 41 7b 32 63 79 72 49 51 6e 73 43 73 30 } //01 00 
		$a_01_1 = {67 79 58 44 56 70 30 76 74 53 35 5a 75 6a 73 } //01 00 
		$a_01_2 = {8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf } //00 00 
	condition:
		any of ($a_*)
 
}