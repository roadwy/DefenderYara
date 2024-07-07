
rule Trojan_Win32_Zenpak_MBJZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 } //1
		$a_01_1 = {61 6e 62 6c 73 62 69 61 6c 6c 35 32 2e 64 6c 6c 00 49 65 65 63 70 6e 45 77 65 65 74 6e 61 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //1
		$a_01_2 = {46 69 74 34 21 78 39 43 68 56 7c 48 6e 44 42 2d 69 67 4c 72 38 45 52 7a 35 37 3d 23 47 73 } //1 Fit4!x9ChV|HnDB-igLr8ERz57=#Gs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}