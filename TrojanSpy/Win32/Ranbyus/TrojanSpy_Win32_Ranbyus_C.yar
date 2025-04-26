
rule TrojanSpy_Win32_Ranbyus_C{
	meta:
		description = "TrojanSpy:Win32/Ranbyus.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 5c 2f 5c 2f 69 62 61 6e 6b 2e 61 6c 66 61 62 61 6e 6b 2e 72 75 } //3 https:\/\/ibank.alfabank.ru
		$a_01_1 = {75 73 65 72 6e 61 6d 65 3d 2e 2a 26 70 61 73 73 77 6f 72 64 3d 2e 2a } //2 username=.*&password=.*
		$a_01_2 = {5b 4d 4f 55 53 45 20 4c 20 25 75 78 25 75 5d } //3 [MOUSE L %ux%u]
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=8
 
}