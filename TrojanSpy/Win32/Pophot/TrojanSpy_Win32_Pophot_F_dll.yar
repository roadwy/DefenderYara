
rule TrojanSpy_Win32_Pophot_F_dll{
	meta:
		description = "TrojanSpy:Win32/Pophot.F!dll,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_02_0 = {50 b9 e8 03 00 00 ba 01 00 00 00 b8 90 01 04 e8 90 01 02 ff ff 8b 55 90 01 01 b9 90 01 04 b8 02 00 00 80 e8 90 01 02 ff ff 8b 45 fc e8 90 01 02 ff ff 83 f8 0a 0f 8f 90 01 02 00 00 8d 45 90 01 01 50 8d 85 7c ff ff ff 50 b9 e8 03 00 00 ba 01 00 00 00 b8 90 01 04 e8 90 01 02 ff ff 8b 95 7c ff ff ff b9 90 01 04 b8 02 00 00 80 e8 90 01 02 ff ff 90 00 } //10
		$a_02_1 = {b9 e8 03 00 00 ba 01 00 00 00 b8 90 01 04 e8 90 01 02 ff ff 8d 45 b4 50 b9 64 00 00 00 ba 01 00 00 00 b8 90 01 04 e8 90 01 02 ff ff 8b 55 b4 90 00 } //10
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_3 = {7a 75 6f 79 75 65 31 36 2e 69 6e 69 } //1 zuoyue16.ini
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_00_5 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d } //1 AVP.TrafficMonConnectionTerm
		$a_00_6 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 AVP.Product_Notification
		$a_00_7 = {63 6a 2e 62 61 74 } //1 cj.bat
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=26
 
}