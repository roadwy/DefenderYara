
rule Worm_Win32_Winlire_A{
	meta:
		description = "Worm:Win32/Winlire.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 65 6c 69 72 00 5c 4d 79 5f 46 6f 74 6f 67 72 61 66 69 2e 65 78 65 00 } //1
		$a_03_1 = {66 c7 43 10 38 00 ba 90 01 04 8d 45 e4 e8 90 01 04 ff 43 1c 33 c0 89 45 f8 8d 45 fc ff 43 1c 8d 55 e4 8d 4d f8 e8 90 00 } //1
		$a_01_2 = {66 c7 43 10 14 00 8b f0 ba 02 00 00 80 8b c6 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}