
rule TrojanSpy_Win32_AshamedWages_D_MTB{
	meta:
		description = "TrojanSpy:Win32/AshamedWages.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe c3 8a 14 1f 00 d0 8a 0c 07 88 0c 1f 88 14 07 00 d1 8a 0c 0f 30 0e 46 ff 4d 14 75 } //5
		$a_01_1 = {89 e5 6a 04 68 00 30 00 00 68 00 00 e0 06 6a 00 ff 15 } //1
		$a_01_2 = {f7 e2 3c 61 72 04 3c 7a 76 0d 2d 21 30 00 00 81 c2 21 30 00 00 eb e9 aa e2 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}