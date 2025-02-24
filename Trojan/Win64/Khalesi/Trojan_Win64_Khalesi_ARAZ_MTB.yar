
rule Trojan_Win64_Khalesi_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c1 44 0f b6 44 0c 34 8d 50 77 83 c0 01 44 31 c2 88 54 0c 34 8b 54 24 30 39 c2 77 e3 } //4
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}