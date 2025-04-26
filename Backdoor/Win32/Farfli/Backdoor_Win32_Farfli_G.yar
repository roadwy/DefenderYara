
rule Backdoor_Win32_Farfli_G{
	meta:
		description = "Backdoor:Win32/Farfli.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 6a 10 5f 8d 0c 06 8b c6 99 f7 ff 8b 44 24 10 8a 04 02 32 01 34 ?? 46 3b 74 24 14 88 01 7c dd } //3
		$a_03_1 = {7e 44 8b 45 08 33 c9 39 4d f8 8a 04 06 7e 10 8a 14 0b 32 d0 80 f2 ?? 41 3b 4d f8 8a c2 7c f0 } //3
		$a_03_2 = {74 1d 8d 85 d8 fe ff ff 50 57 e8 ?? ?? 00 00 85 c0 74 12 8d 85 fc fe ff ff 50 ff 75 08 eb db 8b 9d e0 fe ff ff 57 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3) >=5
 
}