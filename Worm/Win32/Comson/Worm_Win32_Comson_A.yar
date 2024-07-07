
rule Worm_Win32_Comson_A{
	meta:
		description = "Worm:Win32/Comson.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 54 0a 50 33 c0 83 c2 f8 85 d2 76 } //1
		$a_03_1 = {b8 67 66 66 66 80 c2 30 88 94 90 01 02 ff ff ff 90 00 } //1
		$a_03_2 = {75 06 39 7c 08 04 74 90 01 01 40 3b 90 01 01 72 ec 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}