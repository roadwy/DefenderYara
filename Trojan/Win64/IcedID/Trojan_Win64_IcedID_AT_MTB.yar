
rule Trojan_Win64_IcedID_AT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 53 65 47 68 4b 62 47 71 50 4a 42 39 6f 53 63 39 54 31 5a } //01 00  BSeGhKbGqPJB9oSc9T1Z
		$a_01_1 = {42 75 53 5a 72 4c 33 48 6a 36 31 49 4e 74 44 75 30 5a 41 33 4d 6d 5a 70 5a } //01 00  BuSZrL3Hj61INtDu0ZA3MmZpZ
		$a_01_2 = {43 41 55 31 4a 48 76 31 34 49 51 44 72 6f 6f 7a 43 71 51 63 39 58 } //01 00  CAU1JHv14IQDroozCqQc9X
		$a_01_3 = {43 57 4b 6c 53 6a 68 4c 31 4f 69 45 6d 45 41 50 56 78 75 67 6f 63 35 35 72 39 39 41 36 44 58 } //01 00  CWKlSjhL1OiEmEAPVxugoc55r99A6DX
		$a_01_4 = {4a 30 51 6d 56 62 6b 63 63 4e 31 4f 6f 43 38 5a 42 6f 61 4e 37 59 39 71 77 6a 4e 36 71 } //01 00  J0QmVbkccN1OoC8ZBoaN7Y9qwjN6q
		$a_01_5 = {4d 62 38 6a 63 75 4e 68 4f 57 48 30 4e 53 63 4e 38 53 6c 36 74 49 46 64 33 } //00 00  Mb8jcuNhOWH0NScN8Sl6tIFd3
	condition:
		any of ($a_*)
 
}