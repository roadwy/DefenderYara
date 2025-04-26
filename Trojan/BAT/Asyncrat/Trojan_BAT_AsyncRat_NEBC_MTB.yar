
rule Trojan_BAT_AsyncRat_NEBC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 07 00 00 "
		
	strings :
		$a_01_0 = {36 34 64 37 38 61 38 33 2d 39 32 37 34 2d 34 63 64 38 2d 39 64 63 38 2d 65 35 66 37 36 66 30 39 62 61 33 37 } //5 64d78a83-9274-4cd8-9dc8-e5f76f09ba37
		$a_01_1 = {64 00 32 00 6c 00 75 00 5a 00 48 00 64 00 76 00 63 00 79 00 51 00 3d 00 } //4 d2luZHdvcyQ=
		$a_01_2 = {44 6f 74 66 75 73 63 61 74 65 64 5c 77 69 6e 64 77 6f 73 2e 70 64 62 } //4 Dotfuscated\windwos.pdb
		$a_01_3 = {77 69 6e 64 77 6f 73 2e 4d 79 } //2 windwos.My
		$a_01_4 = {47 65 74 50 69 78 65 6c } //2 GetPixel
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_6 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 RPF:SmartAssembly
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=19
 
}