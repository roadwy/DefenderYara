
rule Trojan_Win64_T1558_StealOrForgeKerberosTickets_A{
	meta:
		description = "Trojan:Win64/T1558_StealOrForgeKerberosTickets.A,SIGNATURE_TYPE_PEHSTR,14 00 14 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 6c 00 69 00 73 00 74 00 } //0a 00  kerberos::list
		$a_01_1 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 63 00 6c 00 69 00 73 00 74 00 } //0a 00  kerberos::clist
		$a_01_2 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 68 00 61 00 73 00 68 00 } //0a 00  kerberos::hash
		$a_01_3 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 63 00 } //0a 00  kerberos::ptc
		$a_01_4 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 } //0a 00  kerberos::ptt
		$a_01_5 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 74 00 67 00 74 00 } //0a 00  kerberos::tgt
		$a_01_6 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 6c 00 73 00 61 00 } //0a 00  lsadump::lsa
		$a_01_7 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 } //0a 00  sekurlsa::kerberos
		$a_01_8 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 6b 00 72 00 62 00 74 00 67 00 74 00 } //0a 00  sekurlsa::krbtgt
		$a_01_9 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 74 00 69 00 63 00 6b 00 65 00 74 00 73 00 } //00 00  sekurlsa::tickets
	condition:
		any of ($a_*)
 
}