
rule PWS_Win32_Lolyda_V{
	meta:
		description = "PWS:Win32/Lolyda.V,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 69 63 65 52 6f 75 74 65 45 78 00 } //1
		$a_00_1 = {53 74 61 72 74 53 65 72 76 69 63 65 45 78 00 } //1
		$a_00_2 = {53 74 6f 70 53 65 72 76 69 63 65 45 78 00 } //1 瑓灯敓癲捩䕥x
		$a_00_3 = {6c 65 76 65 6c 73 3d 25 73 26 63 61 73 68 3d 25 73 } //1 levels=%s&cash=%s
		$a_02_4 = {66 ad b9 03 00 00 00 ba 3d 00 00 00 83 6d fc 02 90 13 86 c4 c1 c0 10 86 c4 50 25 00 00 00 fc c1 c0 06 8a 80 ?? ?? ?? ?? aa } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}