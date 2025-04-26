
rule TrojanSpy_Win32_Bancos_XJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.XJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {31 43 6c 69 63 6b 13 00 [0-08] 49 6d 61 67 65 90 10 03 00 43 6c 69 63 6b } //1
		$a_00_1 = {62 6b 6c 63 6f 6d 2e 64 6c 6c 5f 61 72 71 75 69 76 6f 73 } //1 bklcom.dll_arquivos
		$a_00_2 = {73 65 6e 68 61 20 64 65 20 61 63 65 73 73 6f } //1 senha de acesso
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}