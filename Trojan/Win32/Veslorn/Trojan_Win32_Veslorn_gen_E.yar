
rule Trojan_Win32_Veslorn_gen_E{
	meta:
		description = "Trojan:Win32/Veslorn.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b1 72 b0 65 88 4c 24 02 88 4c 24 06 } //1
		$a_01_1 = {c6 44 24 0d 62 88 44 24 0e 88 44 24 0f c6 44 24 10 70 c6 44 24 11 2e 88 4c 24 12 c6 44 24 13 79 88 4c 24 14 c6 44 24 15 00 e8 } //1
		$a_03_2 = {6a 04 52 68 4b e1 22 00 50 ff 15 90 01 04 85 c0 74 10 ff 15 90 01 04 85 c0 75 06 90 00 } //1
		$a_01_3 = {00 5c 5c 2e 5c 53 53 44 54 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}