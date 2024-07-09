
rule TrojanDropper_Win32_Tidola_A{
	meta:
		description = "TrojanDropper:Win32/Tidola.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {85 db 74 0b 83 c6 14 81 fe 59 07 00 00 72 8d } //3
		$a_03_1 = {83 f8 11 75 3d a1 ?? ?? ?? ?? 0f b6 40 02 83 f8 01 74 0e a1 ?? ?? ?? ?? 0f b6 40 02 83 f8 03 } //3
		$a_01_2 = {00 c9 cf b5 c4 b6 af 00 } //1
		$a_01_3 = {00 c8 eb c3 dc b1 a3 bf a8 00 } //1
		$a_00_4 = {61 63 74 3d 26 64 31 30 3d 25 73 26 64 38 30 3d 25 64 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}