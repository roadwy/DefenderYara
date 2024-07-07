
rule TrojanSpy_Win32_Bancos_ACZ{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {bf 01 00 00 00 8b 45 f8 0f b6 44 38 ff 03 c6 b9 ff 00 00 00 99 f7 f9 8b da 8b 45 ec 3b 45 f0 7d 05 ff 45 ec eb 07 c7 45 ec 01 00 00 00 83 f3 10 } //2
		$a_01_1 = {73 65 6e 68 61 63 61 72 64 } //1 senhacard
		$a_01_2 = {73 65 6e 68 61 36 } //1 senha6
		$a_01_3 = {07 4d 4d 64 61 64 6f 73 } //1 䴇摍摡獯
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}