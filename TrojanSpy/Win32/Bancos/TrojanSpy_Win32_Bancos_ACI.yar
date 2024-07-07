
rule TrojanSpy_Win32_Bancos_ACI{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 35 44 6c 50 64 48 74 4f 4e 39 62 4e 34 72 66 4f 74 39 6c 53 73 7a 63 54 35 6e 4e 51 4d 76 61 52 74 54 70 4e 34 44 72 53 64 39 62 52 64 48 4d 50 4e 39 70 51 4d 7a 6b 4e 35 39 72 52 57 } //4 N5DlPdHtON9bN4rfOt9lSszcT5nNQMvaRtTpN4DrSd9bRdHMPN9pQMzkN59rRW
		$a_01_1 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c } //1 AutoConfigURL
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}