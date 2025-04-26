
rule TrojanSpy_Win32_Bancos_AAI{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAI,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 35 be 01 00 00 00 8b 45 ec 0f b6 7c 30 ff 8b 45 e0 0f b6 00 89 45 f4 8d 45 e4 8b d7 2b 55 f4 2b 55 f0 e8 } //10
		$a_01_1 = {50 72 6f 76 69 64 65 72 3d 53 51 4c 4f 4c 45 44 42 2e 31 3b 50 61 73 73 77 6f 72 64 3d } //1 Provider=SQLOLEDB.1;Password=
		$a_01_2 = {54 46 72 6d 55 4e 53 } //1 TFrmUNS
		$a_01_3 = {45 6e 76 6f 49 46 4f 00 45 6e 76 6f 4d 53 4f 00 } //1 湅潶䙉O湅潶卍O
		$a_03_4 = {42 54 53 74 61 63 4d 73 6e 2e 64 6c 6c 00 45 6e 76 6f 4d 53 4f 00 90 09 09 00 f3 02 00 40 40 03 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=11
 
}