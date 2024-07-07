
rule TrojanDropper_Win32_Sirefef_D{
	meta:
		description = "TrojanDropper:Win32/Sirefef.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f9 cd 2d 90 01 02 75 fa 90 00 } //1
		$a_01_1 = {ad 4a 03 c2 ab 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Sirefef_D_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.D,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f9 cd 2d 90 01 02 75 fa 90 00 } //1
		$a_01_1 = {ad 4a 03 c2 ab 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}