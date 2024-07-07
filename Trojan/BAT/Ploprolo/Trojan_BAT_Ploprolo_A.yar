
rule Trojan_BAT_Ploprolo_A{
	meta:
		description = "Trojan:BAT/Ploprolo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 32 56 30 56 47 68 79 5a 57 46 6b 51 32 39 75 64 47 56 34 64 41 3d 3d } //1 U2V0VGhyZWFkQ29udGV4dA==
		$a_01_1 = {56 33 4a 70 64 47 56 51 63 6d 39 6a 5a 58 4e 7a 54 57 56 74 62 33 4a 35 } //1 V3JpdGVQcm9jZXNzTWVtb3J5
		$a_01_2 = {52 6d 39 73 5a 47 56 79 54 6d 46 74 5a 56 78 75 4c 6d 56 34 5a 51 3d 3d } //1 Rm9sZGVyTmFtZVxuLmV4ZQ==
		$a_01_3 = {56 58 42 73 62 32 46 6b 55 6d 56 77 62 33 4a 30 54 47 39 6e 61 57 34 75 59 58 4e 74 65 41 3d 3d } //1 VXBsb2FkUmVwb3J0TG9naW4uYXNteA==
		$a_01_4 = {51 58 5a 68 63 33 52 54 64 6d 4d 3d } //1 QXZhc3RTdmM=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}