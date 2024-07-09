
rule TrojanSpy_Win32_Retsnux_A{
	meta:
		description = "TrojanSpy:Win32/Retsnux.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 75 74 5f 66 69 6c 65 20 3d 20 25 41 5f 53 74 61 72 74 75 70 25 5c 6e 65 74 77 69 6e 2e 65 78 65 } //1 out_file = %A_Startup%\netwin.exe
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 27 6e 65 74 77 69 6e 27 20 63 65 72 74 69 66 69 63 61 74 65 2e } //1 Failed to create 'netwin' certificate.
		$a_01_2 = {46 69 6c 65 41 70 70 65 6e 64 2c 20 25 6b 25 20 2c 20 25 41 5f 41 70 70 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 64 61 74 61 5c 4e 45 54 55 53 52 } //1 FileAppend, %k% , %A_AppData%\Microsoft\data\NETUSR
		$a_03_3 = {73 41 74 74 61 63 68 90 05 05 01 20 3d 90 05 05 01 20 25 41 5f 41 70 70 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 64 61 74 61 5c 4e 45 54 55 53 52 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}