
rule Trojan_Win32_Dapato_DSK_MTB{
	meta:
		description = "Trojan:Win32/Dapato.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 83 e9 08 89 4d f0 8b 55 f8 8b 4d f0 d3 fa 81 e2 ff 00 00 00 8b 45 f4 03 45 ec 88 10 8b 4d ec 83 c1 01 89 4d ec } //2
		$a_01_1 = {32 23 4a 4e 4d 48 58 46 41 40 32 2a 45 44 43 31 56 7d 4a 5a 66 33 4f 4c 4b 58 4d 74 4a 7c 55 } //1 2#JNMHXFA@2*EDC1V}JZf3OLKXMtJ|U
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}