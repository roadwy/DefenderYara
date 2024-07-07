
rule TrojanSpy_Win32_Bancos_MB{
	meta:
		description = "TrojanSpy:Win32/Bancos.MB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 6e 6c 6f 61 00 00 00 ff ff ff ff 06 00 00 00 64 65 64 20 50 72 00 00 ff ff ff ff 03 00 00 00 6f 67 72 00 } //1
		$a_01_1 = {05 00 00 00 61 6d 20 46 69 00 00 00 ff ff ff ff 06 00 00 00 6c 65 73 5c 2a 67 00 00 ff ff ff ff 04 00 00 00 62 2a 2e 2a } //1
		$a_01_2 = {5c 47 00 00 ff ff ff ff 02 00 00 00 62 50 00 00 ff ff ff ff 03 00 00 00 6c 75 67 00 ff ff ff ff 04 00 00 00 69 6e 5c 2a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}