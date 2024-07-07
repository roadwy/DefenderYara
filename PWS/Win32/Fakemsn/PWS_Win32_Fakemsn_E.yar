
rule PWS_Win32_Fakemsn_E{
	meta:
		description = "PWS:Win32/Fakemsn.E,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 45 ec c7 45 f0 01 00 00 00 8b 45 fc 8b 55 f0 0f b6 74 10 ff 8b c7 c1 e0 08 03 f0 8b fe 83 c3 08 83 fb 06 } //4
		$a_01_1 = {83 eb 06 8b cb b8 01 00 00 00 d3 e0 50 8b c7 5a 8b ca } //4
		$a_01_2 = {8b 55 b8 8b 45 f8 8b 80 20 04 00 00 8b 80 70 02 00 00 8b 08 ff 51 74 8d 45 b4 } //4
		$a_01_3 = {5c 6d 73 6e 6c 69 76 65 2e 6c 6f 67 } //1 \msnlive.log
		$a_01_4 = {70 68 70 2e 72 6f 64 61 74 6e 6f 63 2f 6d 6f 63 } //1 php.rodatnoc/moc
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}