
rule Worm_Win32_Lasiaf_B{
	meta:
		description = "Worm:Win32/Lasiaf.B,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 73 00 6d 00 61 00 68 00 61 00 6e 00 69 00 5c 00 41 00 73 00 6d 00 61 00 68 00 61 00 6e 00 69 00 2e 00 76 00 62 00 70 00 } //10 \Asmahani\Asmahani.vbp
		$a_01_1 = {2d 00 4c 00 61 00 73 00 69 00 61 00 66 00 2d 00 } //1 -Lasiaf-
		$a_01_2 = {41 00 73 00 6d 00 61 00 68 00 61 00 6e 00 69 00 27 00 73 00 4d 00 73 00 67 00 2e 00 74 00 78 00 74 00 } //1 Asmahani'sMsg.txt
		$a_01_3 = {4d 00 79 00 76 00 77 00 61 00 } //1 Myvwa
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}