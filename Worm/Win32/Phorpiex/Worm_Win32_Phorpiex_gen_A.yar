
rule Worm_Win32_Phorpiex_gen_A{
	meta:
		description = "Worm:Win32/Phorpiex.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 14 2d 00 57 ff 15 90 01 04 85 c0 74 90 01 01 8b 94 24 90 01 01 00 00 00 8a 84 14 90 01 01 00 00 00 8d 94 14 90 01 01 00 00 00 84 c0 74 90 00 } //1
		$a_03_1 = {01 00 00 ff 15 90 01 04 e8 90 01 04 84 c0 0f 85 90 01 04 8b 35 90 01 04 68 90 01 04 ff d6 85 c0 0f 85 90 01 04 68 90 01 04 ff d6 85 c0 0f 85 90 09 02 00 68 90 90 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}