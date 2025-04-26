
rule PWS_Win32_Jomloon_D{
	meta:
		description = "PWS:Win32/Jomloon.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8a 14 06 32 d1 88 10 40 4f 75 f5 } //2
		$a_03_1 = {75 09 68 d0 07 00 00 ff d3 eb e4 8b b4 24 ?? ?? 00 00 83 7e 24 01 74 09 68 2c 01 00 00 ff d3 eb f1 } //2
		$a_03_2 = {eb 33 83 f8 05 75 0b 8d 54 24 20 bf ?? ?? 00 10 eb 23 83 f8 06 75 0b 8d 54 24 20 bf ?? ?? 00 10 eb 13 83 f8 07 8d 54 24 20 } //2
		$a_01_3 = {55 4b 4f 53 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}