
rule Trojan_Win32_TrickBot_DSK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f3 41 8a 04 2a 30 44 31 ff 3b cf 75 } //2
		$a_01_1 = {32 23 4a 4e 4d 48 58 46 41 40 32 2a 45 44 43 31 56 7d 4a 5a 66 33 4f 4c 4b 58 4d 74 4a 7c 55 } //1 2#JNMHXFA@2*EDC1V}JZf3OLKXMtJ|U
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_TrickBot_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 db 4b 68 2f f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf } //2
		$a_01_1 = {54 79 57 41 43 6b 38 62 74 7d 65 41 33 41 31 32 63 35 54 54 4a 76 4f 6d 59 62 45 } //1 TyWACk8bt}eA3A12c5TTJvOmYbE
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}