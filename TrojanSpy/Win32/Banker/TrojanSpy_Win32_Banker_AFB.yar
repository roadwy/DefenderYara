
rule TrojanSpy_Win32_Banker_AFB{
	meta:
		description = "TrojanSpy:Win32/Banker.AFB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6c 62 6c 42 72 6f 77 73 65 72 41 6e 65 78 61 64 6f 90 02 36 62 6c 6f 71 75 65 90 00 } //02 00 
		$a_00_1 = {62 6c 6f 63 6b 69 6e 70 75 74 } //02 00  blockinput
		$a_00_2 = {67 65 74 65 78 65 } //02 00  getexe
		$a_00_3 = {6d 6f 75 73 65 68 6f 6f 6b } //01 00  mousehook
		$a_00_4 = {66 69 72 65 66 6f 78 2e 65 78 65 } //01 00  firefox.exe
		$a_00_5 = {68 6f 74 6d 61 69 6c } //01 00  hotmail
		$a_00_6 = {62 61 6e 63 6f } //01 00  banco
		$a_00_7 = {2e 63 6f 6d 2e 62 72 } //00 00  .com.br
	condition:
		any of ($a_*)
 
}