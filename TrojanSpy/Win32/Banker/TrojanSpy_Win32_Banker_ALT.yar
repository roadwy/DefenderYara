
rule TrojanSpy_Win32_Banker_ALT{
	meta:
		description = "TrojanSpy:Win32/Banker.ALT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 47 6b 32 31 67 47 } //2 JGk21gG
		$a_01_1 = {55 70 64 61 74 65 72 4c 6f 67 54 65 63 6b } //2 UpdaterLogTeck
		$a_01_2 = {48 4a 49 38 2e 7a 69 70 } //1 HJI8.zip
		$a_01_3 = {49 36 48 38 2e 65 78 65 } //1 I6H8.exe
		$a_03_4 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=7
 
}