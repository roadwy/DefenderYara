
rule TrojanProxy_Win32_Bunitu_L{
	meta:
		description = "TrojanProxy:Win32/Bunitu.L,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {40 89 10 b2 6e 88 50 04 b2 65 86 d6 88 70 08 51 b9 2a 19 78 17 87 d1 } //1
		$a_01_1 = {44 6f 6e 75 72 6f 6c 78 65 74 30 30 30 5c 53 65 72 76 69 63 65 73 5c 58 68 61 72 64 64 42 63 63 65 73 73 } //2 Donurolxet000\Services\XharddBccess
		$a_03_2 = {6e 73 79 2e [0-10] 2e 90 17 04 03 03 03 04 78 79 7a 6e 65 74 63 6f 6d 69 6e 66 6f 00 } //1
		$a_01_3 = {74 72 65 77 2f 31 2e 30 20 32 30 30 20 4f 4b } //1 trew/1.0 200 OK
		$a_03_4 = {63 6c 64 33 2e [0-10] 2e 63 6f 6d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanProxy_Win32_Bunitu_L_2{
	meta:
		description = "TrojanProxy:Win32/Bunitu.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 41 06 6e 80 69 06 21 fe 49 2c fe 41 05 fe 49 08 fe 41 23 fe 49 2d } //3
		$a_01_1 = {40 89 10 b2 6e 88 50 04 b2 65 86 d6 88 70 08 51 b9 2a 19 78 17 87 d1 } //1
		$a_01_2 = {44 6f 6e 75 72 6f 6c 78 65 74 30 30 30 5c 53 65 72 76 69 63 65 73 5c 58 68 61 72 64 64 42 63 63 65 73 73 } //2 Donurolxet000\Services\XharddBccess
		$a_01_3 = {6e 73 31 2e 64 69 64 75 69 74 2e 69 6e 66 6f } //1 ns1.diduit.info
		$a_01_4 = {74 72 65 77 2f 31 2e 30 20 32 30 30 20 4f 4b } //1 trew/1.0 200 OK
		$a_01_5 = {62 72 6b 65 77 6c 6c } //1 brkewll
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}