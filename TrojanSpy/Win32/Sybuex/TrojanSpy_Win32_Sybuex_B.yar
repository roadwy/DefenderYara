
rule TrojanSpy_Win32_Sybuex_B{
	meta:
		description = "TrojanSpy:Win32/Sybuex.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {77 77 77 2e 63 75 ?? ?? ?? 2e 63 6f 6d 2f [0-16] 74 61 6b [0-08] 2e 65 78 65 } //10
		$a_00_1 = {6c 65 67 65 6e 64 20 6f 66 20 6d 69 72 } //10 legend of mir
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 69 6e 66 5c 73 70 61 74 69 64 2e 69 6e 66 } //1 C:\WINDOWS\inf\spatid.inf
		$a_00_3 = {73 76 63 63 68 6f 73 74 65 72 2e 65 78 65 } //1 svcchoster.exe
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=22
 
}