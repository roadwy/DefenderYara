
rule Worm_Win32_Mariofev_gen_A{
	meta:
		description = "Worm:Win32/Mariofev.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 cc 01 00 00 68 68 01 00 00 e8 ?? ?? 00 00 69 c0 e8 03 00 00 83 c4 10 50 ff d3 } //3
		$a_01_1 = {8b 45 0c 8a 04 07 32 c3 fe c3 80 fb ff 88 45 ec 76 02 32 db ff 75 ec } //2
		$a_01_2 = {43 50 55 49 6e 66 6f 3a 43 6f 75 6e 74 3a 25 75 20 54 79 70 65 3a 25 75 } //1 CPUInfo:Count:%u Type:%u
		$a_01_3 = {4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 } //1 KasperskyLab\protected\AVP7
		$a_01_4 = {6b 65 5f 54 65 72 6d 69 6e 61 74 65 4b 65 72 6e 65 6c 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}