
rule TrojanDropper_Win32_Zampol_A_bit{
	meta:
		description = "TrojanDropper:Win32/Zampol.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 6f 64 61 67 65 28 62 42 75 66 66 65 72 2c 73 72 76 29 } //1 decodage(bBuffer,srv)
		$a_01_1 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 } //1 TVqQAAMAAAAEAAAA
		$a_01_2 = {6c 69 62 3a 3d 22 75 73 65 72 33 32 2e 64 6c 6c 5c 43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 57 22 } //1 lib:="user32.dll\CallWindowProcW"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}