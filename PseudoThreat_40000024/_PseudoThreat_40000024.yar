
rule _PseudoThreat_40000024{
	meta:
		description = "!PseudoThreat_40000024,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa4 01 ffffffa4 01 09 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 65 6e 74 69 6f 6e 21 } //100 Attention!
		$a_01_1 = {52 65 6d 6f 76 61 62 6c 65 } //100 Removable
		$a_00_2 = {72 65 62 6f 6f 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //100 reboot your computer
		$a_00_3 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //50 createtoolhelp32snapshot
		$a_01_4 = {64 65 6c 20 } //50 del 
		$a_01_5 = {4d 65 64 69 61 2d 43 6f 64 65 63 } //10 Media-Codec
		$a_00_6 = {2e 43 68 6c } //10 .Chl
		$a_00_7 = {76 69 64 65 6f } //10 video
		$a_00_8 = {53 4f 46 54 57 41 52 45 5c 47 52 45 41 54 49 53 5c 52 45 47 52 55 4e 32 5c } //-500 SOFTWARE\GREATIS\REGRUN2\
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*-500) >=420
 
}