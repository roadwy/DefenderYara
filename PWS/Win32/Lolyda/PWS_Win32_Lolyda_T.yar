
rule PWS_Win32_Lolyda_T{
	meta:
		description = "PWS:Win32/Lolyda.T,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 48 42 53 65 72 76 69 63 65 33 32 00 53 79 73 74 65 6d 2e 65 78 65 } //10 潓瑦慷敲䵜捩潲潳瑦坜湩潤獷䍜牵敲瑮敖獲潩屮畒n䉈敓癲捩㍥2祓瑳浥攮數
		$a_01_1 = {53 74 6f 70 53 65 72 76 69 63 65 45 78 00 5c 00 53 74 61 72 74 53 65 72 76 69 63 65 45 78 } //4 瑓灯敓癲捩䕥x\瑓牡却牥楶散硅
		$a_01_2 = {48 42 49 6e 6a 65 63 74 33 32 } //4 HBInject32
		$a_00_3 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //4 AppInit_DLLs
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_00_3  & 1)*4) >=12
 
}