
rule PWS_Win32_Nemim_A{
	meta:
		description = "PWS:Win32/Nemim.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 08 6a 33 8d 4c 24 0c b2 52 50 51 c6 44 24 14 1e } //1
		$a_01_1 = {b8 56 55 55 55 8d 0c bd 00 00 00 00 f7 e9 8b c2 c1 e8 1f 8d 4c 02 04 51 e8 } //1
		$a_01_2 = {83 c4 18 33 f6 33 ff 83 fe 10 7d 23 33 c0 8d } //1
		$a_01_3 = {a1 60 f3 82 00 83 f8 01 0f 8f 7a 05 00 00 85 c0 0f 85 c3 00 00 00 8b } //1
		$a_01_4 = {2f 68 74 6d 6c 2f 64 6f 63 75 2e 70 68 70 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}