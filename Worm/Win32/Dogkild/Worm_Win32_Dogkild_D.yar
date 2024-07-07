
rule Worm_Win32_Dogkild_D{
	meta:
		description = "Worm:Win32/Dogkild.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 e0 01 00 00 68 80 02 00 00 6a 64 6a 64 68 00 00 cf 00 } //2
		$a_00_1 = {83 f8 03 74 0c 8d 54 24 08 52 ff d6 83 f8 02 75 0d } //2
		$a_00_2 = {2f 69 6d 20 65 67 75 69 2e 65 78 65 20 2f 66 } //1 /im egui.exe /f
		$a_00_3 = {64 65 6c 65 74 65 20 52 73 52 61 76 4d 6f 6e } //1 delete RsRavMon
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}