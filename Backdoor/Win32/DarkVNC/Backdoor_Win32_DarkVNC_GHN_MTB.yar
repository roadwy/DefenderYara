
rule Backdoor_Win32_DarkVNC_GHN_MTB{
	meta:
		description = "Backdoor:Win32/DarkVNC.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 54 53 51 c7 44 24 ?? 75 65 72 79 c7 44 24 ?? 53 65 73 73 c7 44 24 ?? 69 6f 6e 49 c7 44 24 ?? 6e 66 6f 72 c7 44 24 ?? 6d 61 74 69 c7 44 24 ?? 6f 6e 57 00 ff d6 } //10
		$a_01_1 = {8b 4c 24 04 68 07 80 00 00 8b 41 04 8a 40 01 32 01 2c 12 a2 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}