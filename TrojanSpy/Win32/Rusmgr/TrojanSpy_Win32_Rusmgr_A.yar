
rule TrojanSpy_Win32_Rusmgr_A{
	meta:
		description = "TrojanSpy:Win32/Rusmgr.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {8d 74 31 fc 8d 7c 39 fc c1 f9 02 78 ?? fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc } //1
		$a_00_1 = {50 25 53 25 56 25 59 25 5c 25 } //1 P%S%V%Y%\%
		$a_00_2 = {52 75 6e 4d 73 67 72 73 } //1 RunMsgrs
		$a_00_3 = {52 43 50 54 20 54 4f 3a 3c } //1 RCPT TO:<
		$a_00_4 = {48 65 6c 6f 4e 61 6d 65 } //1 HeloName
		$a_00_5 = {55 73 65 45 68 6c 6f } //1 UseEhlo
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}