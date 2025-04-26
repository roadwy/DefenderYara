
rule TrojanSpy_Win32_Verbscut_A{
	meta:
		description = "TrojanSpy:Win32/Verbscut.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //2 Software\Microsoft\Internet Explorer\IntelliForms\Storage2
		$a_01_1 = {54 56 72 42 73 63 54 68 72 65 61 64 } //3 TVrBscThread
		$a_01_2 = {75 49 45 39 5f 44 65 63 6f 64 65 } //3 uIE9_Decode
		$a_01_3 = {53 65 6e 68 61 20 2e 3a 20 25 73 } //5 Senha .: %s
		$a_01_4 = {55 52 4c 20 2e 2e 2e 3a 20 25 73 } //5 URL ...: %s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=18
 
}