
rule TrojanSpy_Win32_Fastpos_A_bit{
	meta:
		description = "TrojanSpy:Win32/Fastpos.A!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 2f 00 2f 00 63 00 64 00 6f 00 73 00 79 00 73 00 2e 00 70 00 68 00 70 00 } //1 %s//cdosys.php
		$a_01_1 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 26 00 6c 00 6f 00 67 00 3d 00 57 00 4e 00 44 00 25 00 73 00 4b 00 42 00 44 00 25 00 73 00 } //1 keylog&log=WND%sKBD%s
		$a_01_2 = {6e 00 65 00 77 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 26 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 25 00 53 00 26 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 25 00 53 00 26 00 6f 00 73 00 3d 00 25 00 53 00 26 00 61 00 72 00 63 00 68 00 69 00 74 00 65 00 63 00 74 00 75 00 72 00 65 00 3d 00 25 00 53 00 } //1 newcomputer&username=%S&computername=%S&os=%S&architecture=%S
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}