
rule TrojanSpy_Win32_Bancos_AJV{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 41 00 4c 00 32 00 38 00 30 00 44 00 45 00 42 00 43 00 41 00 00 00 } //1
		$a_01_1 = {32 00 38 00 30 00 44 00 45 00 42 00 43 00 41 00 3a 00 3a 00 57 00 4b 00 00 00 } //1
		$a_01_2 = {7b 00 30 00 31 00 45 00 39 00 38 00 30 00 36 00 37 00 45 00 41 00 39 00 45 00 33 00 38 00 30 00 39 00 30 00 7d 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}