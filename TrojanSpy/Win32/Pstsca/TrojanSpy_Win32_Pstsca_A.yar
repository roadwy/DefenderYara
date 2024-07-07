
rule TrojanSpy_Win32_Pstsca_A{
	meta:
		description = "TrojanSpy:Win32/Pstsca.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 66 20 2f 74 20 2f 69 6d 20 6f 75 74 6c 6f 6f 6b 2e 65 78 65 } //1 taskkill.exe /f /t /im outlook.exe
		$a_01_1 = {66 83 f8 70 75 53 66 8b 4e 04 e8 bc ff ff ff 66 83 f8 73 75 44 66 8b 4e 06 e8 ad ff ff ff 66 83 f8 74 75 35 66 39 56 08 75 2f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}