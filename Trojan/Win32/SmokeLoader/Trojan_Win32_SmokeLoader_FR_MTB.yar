
rule Trojan_Win32_SmokeLoader_FR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 51 8d 45 90 01 01 50 c7 05 90 01 08 e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 83 25 90 01 05 50 90 00 } //1
		$a_00_1 = {66 65 79 69 63 75 6a 65 79 2d 6d 69 76 69 64 65 66 65 66 75 74 65 2d 6a 61 73 69 39 32 5f 64 6f 6d 75 2e 70 64 62 } //1 feyicujey-mividefefute-jasi92_domu.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}