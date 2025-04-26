
rule TrojanSpy_Win32_Bancos_ACV{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 5f 67 69 64 2e 62 61 74 } //1 encrypt_gid.bat
		$a_01_1 = {ff 3a 7e 35 32 2c 31 25 25 57 49 4e 44 49 52 25 5c 25 ff 3a 7e 31 38 2c 31 25 25 ff 3a 7e 32 33 2c 31 25 25 ff 3a 7e 31 38 2c 31 25 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}