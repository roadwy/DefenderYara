
rule Backdoor_Win32_Farfli_DC{
	meta:
		description = "Backdoor:Win32/Farfli.DC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 29 57 c6 44 24 2a 4f c6 44 24 2b 4c c6 44 24 2c 46 88 5c 24 2d c6 44 24 18 3a c6 44 24 19 32 c6 44 24 1a 30 c6 44 24 1b 31 c6 44 24 1c 35 c6 44 24 1d 2d c6 44 24 1e 56 c6 44 24 1f 49 c6 44 24 20 50 } //1
		$a_01_1 = {8b 44 24 0c b9 ab 05 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 0c 80 c2 3d 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}