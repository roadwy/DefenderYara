
rule Trojan_Win32_Koobface_gen_M{
	meta:
		description = "Trojan:Win32/Koobface.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {3f 61 63 74 69 6f 6e 3d 62 73 26 76 3d 32 30 26 61 3d (6e 61 6d 65 73|67 65 74 75 6e 72 65 61 64 79) } //1
		$a_00_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0a 20 64 65 6c 20 22 25 73 22 } //1
		$a_02_2 = {62 6c 6f 67 [0-10] 2e 63 6f 6d } //1
		$a_00_3 = {23 42 4c 41 43 4b 4c 41 42 45 4c } //1 #BLACKLABEL
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}