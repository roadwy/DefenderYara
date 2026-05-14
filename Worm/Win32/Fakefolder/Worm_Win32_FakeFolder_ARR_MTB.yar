
rule Worm_Win32_FakeFolder_ARR_MTB{
	meta:
		description = "Worm:Win32/FakeFolder.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 00 6d 00 33 00 32 00 5c 00 66 00 6c 00 61 00 73 00 68 00 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00 } //15 em32\flash.exe /f
		$a_81_1 = {66 6c 61 73 68 2e 65 78 65 } //4 flash.exe
		$a_81_2 = {73 63 72 65 65 6e 20 74 61 6b 65 64 } //1 screen taked
	condition:
		((#a_01_0  & 1)*15+(#a_81_1  & 1)*4+(#a_81_2  & 1)*1) >=20
 
}