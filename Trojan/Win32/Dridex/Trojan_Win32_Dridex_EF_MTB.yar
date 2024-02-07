
rule Trojan_Win32_Dridex_EF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {66 72 70 6f 6e 67 68 72 70 4f 6c 65 74 6e 66 65 72 63 72 72 } //03 00  frponghrpOletnfercrr
		$a_81_1 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //03 00  kernel32.Sleep
		$a_81_2 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //03 00  rpidebbfll.pdb
		$a_81_3 = {6c 6c 6f 73 65 77 77 71 2e 6c 6c } //03 00  llosewwq.ll
		$a_81_4 = {52 70 63 4d 67 6d 74 49 73 53 65 72 76 65 72 4c 69 73 74 65 6e 69 6e 67 } //03 00  RpcMgmtIsServerListening
		$a_81_5 = {46 74 70 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //03 00  FtpFindFirstFileA
		$a_81_6 = {4e 6f 74 69 66 79 43 68 61 6e 67 65 45 76 65 6e 74 4c 6f 67 } //00 00  NotifyChangeEventLog
	condition:
		any of ($a_*)
 
}