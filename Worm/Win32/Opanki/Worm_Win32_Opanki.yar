
rule Worm_Win32_Opanki{
	meta:
		description = "Worm:Win32/Opanki,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {5f 4f 73 63 61 72 5f 53 74 61 74 75 73 4e 6f 74 69 66 79 } //1 _Oscar_StatusNotify
		$a_01_1 = {5f 4f 73 63 61 72 5f 49 63 6f 6e 42 74 6e } //1 _Oscar_IconBtn
		$a_01_2 = {55 68 23 4e 00 00 68 11 01 00 00 57 ff 15 } //2
		$a_03_3 = {68 8b 00 00 00 68 11 01 00 00 ff 74 [0-40] 6a 25 68 00 01 00 00 } //3
		$a_03_4 = {41 49 4d 5f 49 4d 65 73 73 61 67 65 [0-05] 5f 4f 73 63 61 72 5f 54 72 65 65 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3) >=6
 
}