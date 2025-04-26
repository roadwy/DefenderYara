
rule TrojanSpy_Win32_Dold_A{
	meta:
		description = "TrojanSpy:Win32/Dold.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b7 fb 8b 55 00 0f b6 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 0f af 35 ?? ?? ?? ?? 66 03 35 ?? ?? ?? ?? 43 66 ff 4c 24 04 75 c0 } //10
		$a_01_1 = {0f 84 6c 01 00 00 2d cd ab cd ab 0f 84 a2 02 00 00 2d 33 54 32 54 0f 84 5b 02 00 00 } //10
		$a_81_2 = {73 65 72 61 73 61 2e 63 6f 6d 2e 62 72 } //1 serasa.com.br
		$a_81_3 = {73 70 63 2e 6f 72 67 2e 62 72 } //1 spc.org.br
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=20
 
}