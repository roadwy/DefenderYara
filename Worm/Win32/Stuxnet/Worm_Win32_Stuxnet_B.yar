
rule Worm_Win32_Stuxnet_B{
	meta:
		description = "Worm:Win32/Stuxnet.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 04 00 00 00 0f b7 04 4f 66 83 f8 30 72 b9 66 83 f8 39 77 b3 0f b7 c0 8d 44 30 d0 99 } //1
		$a_01_1 = {ff d7 ff d3 50 6a 01 6a 1c 56 ff d7 56 6a 02 6a 06 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}