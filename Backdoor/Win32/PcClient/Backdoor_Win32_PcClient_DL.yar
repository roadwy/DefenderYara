
rule Backdoor_Win32_PcClient_DL{
	meta:
		description = "Backdoor:Win32/PcClient.DL,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {c6 85 58 ff ff ff 5c c6 85 59 ff ff ff 73 c6 85 5a ff ff ff 76 c6 85 5b ff ff ff 63 c6 85 5c ff ff ff 68 c6 85 5d ff ff ff 6f c6 85 5e ff ff ff 73 c6 85 5f ff ff ff 74 c6 85 60 ff ff ff 2e c6 85 61 ff ff ff 65 c6 85 62 ff ff ff 78 c6 85 63 ff ff ff 65 80 a5 54 fe ff ff 00 } //10
		$a_01_1 = {33 c0 33 c0 0f 84 03 00 00 00 2c 2d 2e 58 80 a5 fc fe ff ff 00 6a 3f 59 33 c0 8d bd fd fe ff ff } //3
		$a_00_2 = {6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 } //1 myparentthreadid
		$a_00_3 = {25 73 25 30 37 78 2e 69 6d 69 } //1 %s%07x.imi
		$a_00_4 = {47 6c 6f 62 61 6c 5c 70 73 25 30 37 78 } //1 Global\ps%07x
		$a_00_5 = {6a 65 61 6e 2e 35 32 30 38 31 35 2e 63 6f 6d 2f 6d 73 2f 69 70 2e 72 61 72 } //1 jean.520815.com/ms/ip.rar
		$a_00_6 = {74 68 75 6e 64 65 72 35 } //1 thunder5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=14
 
}