
rule Trojan_Win32_Farfli_MAC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 76 4c 6e 63 70 79 30 } //1 .vLncpy0
		$a_01_1 = {2e 76 4c 6e 63 70 79 31 } //1 .vLncpy1
		$a_01_2 = {50 61 74 68 46 69 6e 64 46 69 6c 65 4e 61 6d 65 } //1 PathFindFileName
		$a_00_3 = {79 6d ee b0 b0 e8 2e 7a 9b b5 f3 32 e7 c4 2b 9c e0 85 da 87 f7 2a 71 79 eb c1 aa c5 dd 0e c9 f1 ea 14 9f 91 3c af b2 0c 8d c4 53 f9 9c ce 99 f4 0e dc 7c 22 b6 43 96 cc 48 9c 34 bd da d1 c5 4e df 43 d6 50 58 5e 25 3d 79 21 6d 55 03 68 0f a9 03 ff a9 1e c1 d7 38 fd 09 d4 6f 91 26 19 45 e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}