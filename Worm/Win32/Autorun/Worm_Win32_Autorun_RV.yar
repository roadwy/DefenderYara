
rule Worm_Win32_Autorun_RV{
	meta:
		description = "Worm:Win32/Autorun.RV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 00 25 00 20 00 3d 00 20 00 6e 00 65 00 70 00 6f 00 7c 00 31 00 25 00 20 00 3d 00 20 00 6e 00 6f 00 63 00 69 00 7c 00 5d 00 6e 00 75 00 72 00 6f 00 74 00 75 00 61 00 5b 00 } //1 1% = nepo|1% = noci|]nurotua[
		$a_01_1 = {66 00 6e 00 69 00 2e 00 6e 00 75 00 72 00 6f 00 74 00 75 00 61 00 } //1 fni.nurotua
		$a_01_2 = {5e 21 00 04 00 71 78 ff 00 0e 6c 78 ff f5 03 00 00 00 c7 1c 5a 01 00 2a 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}