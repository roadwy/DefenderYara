
rule Backdoor_Win32_Nervos_A{
	meta:
		description = "Backdoor:Win32/Nervos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 a4 32 de a6 8b e8 } //2
		$a_01_1 = {80 3e 78 75 3d 80 7e 01 78 75 37 80 7e 02 78 75 31 38 5e 03 } //2
		$a_00_2 = {20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 } //1  allowedprogram "%s"
		$a_00_3 = {4e 46 3a 25 69 2c 25 58 } //1 NF:%i,%X
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}