
rule Trojan_Win64_SpyBoy_SA_MTB{
	meta:
		description = "Trojan:Win64/SpyBoy.SA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 65 72 6d 69 6e 61 74 6f 72 2e 73 79 73 } //1 Terminator.sys
		$a_01_1 = {54 65 72 6d 69 6e 61 74 69 6e 67 20 41 4c 4c 20 45 44 52 2f 58 44 52 2f 41 56 73 } //1 Terminating ALL EDR/XDR/AVs
		$a_01_2 = {5a 00 65 00 6d 00 61 00 6e 00 61 00 41 00 6e 00 74 00 69 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //1 ZemanaAntiMalware
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 61 6e 61 73 68 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 7a 61 6e 5c 78 36 34 5c 44 65 62 75 67 5c 7a 61 6e 2e 70 64 62 } //1 C:\Users\anash\source\repos\zan\x64\Debug\zan.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}