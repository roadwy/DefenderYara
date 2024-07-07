
rule PWS_Win32_Fareit_VE_MTB{
	meta:
		description = "PWS:Win32/Fareit.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {4b 38 f4 8b 17 f7 c1 90 01 04 31 da 66 85 d0 39 ca 75 90 00 } //2
		$a_00_1 = {2a 22 3b f0 13 36 87 0b 08 57 25 33 0a 84 14 aa 16 17 eb } //2
		$a_00_2 = {31 f1 16 17 eb } //1
		$a_02_3 = {8d 81 63 bc ae 1e 8a 03 50 b8 90 01 04 3d 90 01 04 0f 85 90 01 04 58 68 90 01 04 83 c4 90 01 01 89 0c 18 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}