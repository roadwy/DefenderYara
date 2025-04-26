
rule TrojanDropper_Win32_Bamital_G{
	meta:
		description = "TrojanDropper:Win32/Bamital.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 81 7e 1a bb 07 74 0b 66 9d b8 01 00 00 00 c9 c2 04 00 } //1
		$a_01_1 = {c6 07 5c c7 47 01 74 65 6d 70 c7 47 05 2e 74 6d 70 c6 47 09 00 6a 00 } //1
		$a_01_2 = {3c 24 72 0c 3c 3d 77 08 04 30 04 07 04 06 eb 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}