
rule TrojanDropper_Win32_EyeStye{
	meta:
		description = "TrojanDropper:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 43 4c 45 41 4e 53 57 45 45 50 5f 5f 00 } //1
		$a_01_1 = {2a 44 72 6f 70 70 65 72 2a 21 6d 61 69 6e 20 3a 20 43 72 65 61 74 65 4d 75 74 65 78 2d 3e 45 52 52 4f 52 5f 41 4c 52 45 41 44 59 5f 45 58 49 53 54 53 00 } //1
		$a_01_2 = {2a 44 72 6f 70 70 65 72 2a 20 3a 20 42 4f 54 5f 56 45 52 53 49 4f 4e 20 3d 20 25 64 2c 20 50 49 44 20 3d 20 25 64 2c 20 73 7a 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 20 3d 20 22 25 73 22 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}