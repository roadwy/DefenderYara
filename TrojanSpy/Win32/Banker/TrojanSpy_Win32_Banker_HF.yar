
rule TrojanSpy_Win32_Banker_HF{
	meta:
		description = "TrojanSpy:Win32/Banker.HF,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 0a 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {2d 2d 3d 5f 4e 65 78 74 50 61 72 74 5f 32 } //10 --=_NextPart_2
		$a_00_2 = {41 41 5f 64 6f 4d 53 4e } //10 AA_doMSN
		$a_00_3 = {4c 69 73 74 61 4d 53 4e 45 6e 76 69 61 72 } //10 ListaMSNEnviar
		$a_02_4 = {4d 61 69 6c 41 67 65 6e 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 65 6c 6f 4e 61 6d 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 73 65 45 68 6c 6f } //2
		$a_00_5 = {56 65 72 69 66 69 63 61 53 65 4a 61 46 6f 69 } //2 VerificaSeJaFoi
		$a_00_6 = {57 53 41 53 65 6e 64 } //1 WSASend
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_8 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_00_9 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=44
 
}