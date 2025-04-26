
rule Worm_Win32_Neeris_gen_C{
	meta:
		description = "Worm:Win32/Neeris.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {88 16 8a 09 8b 75 ?? 03 ca 23 c8 03 f3 8a 8c 0d ?? ?? ff ff 30 0e 43 3b 5d ?? 89 5d ?? 72 } //1
		$a_01_1 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15 } //1
		$a_03_2 = {68 88 13 00 00 ff 15 ?? ?? ?? ?? 45 83 fd 06 7c ?? 68 30 75 00 00 57 6a 01 53 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}