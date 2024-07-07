
rule TrojanSpy_Win32_Bancos_JQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.JQ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 63 41 70 70 70 2e 65 78 65 } //1 C:\WINDOWS\system32\ccAppp.exe
		$a_01_1 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 70 61 64 5c 73 63 70 49 42 43 66 67 2e 62 69 6e } //1 C:\Arquivos de programas\Scpad\scpIBCfg.bin
		$a_01_2 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 47 62 50 6c 75 67 69 6e 5c 67 62 70 73 76 2e 65 78 65 } //1 C:\Arquivos de programas\GbPlugin\gbpsv.exe
		$a_01_3 = {43 3a 2f 57 49 4e 44 4f 57 53 2f 73 79 73 74 65 6d 33 32 2f 73 73 68 69 62 2e 64 6c 6c } //1 C:/WINDOWS/system32/sshib.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}