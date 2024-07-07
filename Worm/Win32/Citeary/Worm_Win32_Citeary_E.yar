
rule Worm_Win32_Citeary_E{
	meta:
		description = "Worm:Win32/Citeary.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 41 7c 21 8b 4d 08 0f be 11 83 fa 5a 7f 16 8b 45 f4 0f af 45 fc 8b 4d 08 0f be 11 8d 44 10 20 } //1
		$a_03_1 = {68 09 20 22 00 8b 55 90 01 02 ff 15 90 01 04 68 b8 0b 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}