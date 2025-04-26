
rule Trojan_BAT_AsyncRAT_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {76 62 4d 6b 53 37 5a 6c 65 66 76 } //vbMkS7Zlefv  2
		$a_01_1 = {7b 31 61 30 33 65 34 34 30 2d 33 32 39 37 2d 34 38 34 34 2d 38 61 38 34 2d 63 61 33 37 31 65 64 64 33 66 39 30 7d } //2 {1a03e440-3297-4844-8a84-ca371edd3f90}
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //2 GetExecutingAssembly
	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_BAT_AsyncRAT_ARAZ_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 33 7e ?? ?? ?? 04 11 04 6f ?? ?? ?? 0a 09 33 1e 06 7e ?? ?? ?? 04 11 04 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 14 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 32 bf 08 17 58 0c 08 07 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARAZ_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {78 75 5a 69 54 71 67 64 64 75 42 78 69 73 78 55 50 4d 46 30 47 37 41 33 6b 6a 37 53 78 38 57 4c } //xuZiTqgdduBxisxUPMF0G7A3kj7Sx8WL  2
		$a_03_1 = {00 06 07 02 07 91 28 ?? ?? ?? 0a 9d 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e5 } //2
		$a_01_2 = {2e 72 65 73 6f 75 72 63 65 73 } //2 .resources
	condition:
		((#a_80_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}