
rule Ransom_Win32_LockEye_YAB_MTB{
	meta:
		description = "Ransom:Win32/LockEye.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {8c 97 91 92 e0 90 9f 8c 98 ad 9b 94 9b 9d 8c e0 8c 98 9b e0 89 91 8e 95 97 92 99 e0 9c 97 8e 9b 9d 8c 91 8e 87 } //2
		$a_01_1 = {32 00 33 00 30 00 42 00 43 00 33 00 42 00 33 00 36 00 41 00 34 00 36 00 44 00 42 00 30 00 44 00 45 00 36 00 39 00 32 00 46 00 34 00 37 00 44 00 35 00 39 00 31 00 31 00 33 00 31 00 39 00 30 00 38 00 33 00 35 } //2
		$a_01_2 = {5a 50 8b 5c 24 0c 6b db ff 53 } //10
		$a_01_3 = {8b 45 08 8b 4d 0c 8b 11 89 10 8b 45 08 83 c0 04 89 45 08 8b 4d 0c 83 c1 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1) >=15
 
}