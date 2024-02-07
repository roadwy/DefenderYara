
rule TrojanSpy_Win32_Rusmgr_A{
	meta:
		description = "TrojanSpy:Win32/Rusmgr.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 74 31 fc 8d 7c 39 fc c1 f9 02 78 90 01 01 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 90 00 } //01 00 
		$a_00_1 = {50 25 53 25 56 25 59 25 5c 25 } //01 00  P%S%V%Y%\%
		$a_00_2 = {52 75 6e 4d 73 67 72 73 } //01 00  RunMsgrs
		$a_00_3 = {52 43 50 54 20 54 4f 3a 3c } //01 00  RCPT TO:<
		$a_00_4 = {48 65 6c 6f 4e 61 6d 65 } //01 00  HeloName
		$a_00_5 = {55 73 65 45 68 6c 6f } //00 00  UseEhlo
	condition:
		any of ($a_*)
 
}