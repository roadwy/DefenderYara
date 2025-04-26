
rule Trojan_Win32_FakeAV_AG_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 63 64 65 64 69 74 2e 65 78 65 20 2d 73 65 74 } //2 bcdedit.exe -set
		$a_01_1 = {5a 53 54 53 49 47 4e 49 4e 47 20 4f 4e } //2 ZSTSIGNING ON
		$a_01_2 = {4a 00 53 00 44 00 41 00 2e 00 45 00 58 00 45 00 } //2 JSDA.EXE
		$a_01_3 = {50 00 72 00 6f 00 32 00 33 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //2 Pro23ctVersion
		$a_01_4 = {57 5f 20 61 48 } //2 W_ aH
		$a_01_5 = {44 37 74 6f 67 45 } //2 D7togE
		$a_01_6 = {68 75 74 64 6f 77 6e 50 74 69 6c } //2 hutdownPtil
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}