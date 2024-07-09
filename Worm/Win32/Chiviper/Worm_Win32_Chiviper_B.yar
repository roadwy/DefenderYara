
rule Worm_Win32_Chiviper_B{
	meta:
		description = "Worm:Win32/Chiviper.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 3e 33 d2 59 f7 f1 (46|47) 83 90 03 01 01 fe ff 08 8a 82 ?? ?? ?? ?? 88 44 90 03 01 01 35 3d f3 7c e4 8d 85 f0 fe ff ff 50 68 04 01 00 00 ff 15 } //1
		$a_03_1 = {68 40 77 1b 00 (ff 15 ?? ?? ??|?? ff ?? e9) } //1
		$a_01_2 = {25 73 5c 25 73 2e 70 69 66 00 } //1
		$a_01_3 = {5c 77 73 6f 63 6b 33 32 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}