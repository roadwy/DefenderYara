
rule TrojanSpy_BAT_Rinlogol_A{
	meta:
		description = "TrojanSpy:BAT/Rinlogol.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 00 69 00 6e 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 3a 00 3a 00 3a 00 20 00 7b 00 30 00 7d 00 20 00 28 00 7b 00 31 00 7d 00 29 00 } //1 Rin Logger ::: {0} ({1})
		$a_01_1 = {4c 00 6f 00 67 00 73 00 20 00 53 00 65 00 6e 00 74 00 21 00 } //1 Logs Sent!
		$a_01_2 = {43 00 6c 00 6f 00 63 00 6b 00 20 00 54 00 69 00 63 00 6b 00 21 00 } //1 Clock Tick!
		$a_01_3 = {75 00 73 00 65 00 72 00 33 00 32 00 3a 00 53 00 65 00 74 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 48 00 6f 00 6f 00 6b 00 45 00 78 00 41 00 } //1 user32:SetWindowsHookExA
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}