
rule Trojan_Win64_T1003_OsCredentialDumping_A{
	meta:
		description = "Trojan:Win64/T1003_OsCredentialDumping.A,SIGNATURE_TYPE_PEHSTR,14 00 14 00 16 00 00 "
		
	strings :
		$a_01_0 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 6d 00 62 00 63 00 } //10 lsadump::mbc
		$a_01_1 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 6e 00 65 00 74 00 73 00 79 00 6e 00 63 00 } //10 lsadump::netsync
		$a_01_2 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 74 00 72 00 75 00 73 00 74 00 } //10 lsadump::trust
		$a_01_3 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 61 00 61 00 64 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 } //10 misc::aadcookie
		$a_01_4 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 61 00 64 00 64 00 73 00 69 00 64 00 } //10 misc::addsid
		$a_01_5 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 69 00 65 00 73 00 } //10 misc::shadowcopies
		$a_01_6 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 6e 00 67 00 63 00 73 00 69 00 67 00 6e 00 } //10 misc::ngcsign
		$a_01_7 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 73 00 63 00 63 00 6d 00 } //10 misc::sccm
		$a_01_8 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 64 00 70 00 61 00 70 00 69 00 } //10 sekurlsa::dpapi
		$a_01_9 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 64 00 70 00 61 00 70 00 69 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //10 sekurlsa::dpapisystem
		$a_01_10 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 65 00 6b 00 65 00 79 00 73 00 } //10 sekurlsa::ekeys
		$a_01_11 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 6c 00 6f 00 67 00 6f 00 6e 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //10 sekurlsa::logonpasswords
		$a_01_12 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 6d 00 73 00 76 00 } //10 sekurlsa::msv
		$a_01_13 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 74 00 72 00 75 00 73 00 74 00 } //10 sekurlsa::trust
		$a_01_14 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 74 00 73 00 70 00 6b 00 67 00 } //10 sekurlsa::tspkg
		$a_01_15 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 77 00 64 00 69 00 67 00 65 00 73 00 74 00 } //10 sekurlsa::wdigest
		$a_01_16 = {74 00 6f 00 6b 00 65 00 6e 00 3a 00 3a 00 6c 00 69 00 73 00 74 00 } //10 token::list
		$a_01_17 = {74 00 6f 00 6b 00 65 00 6e 00 3a 00 3a 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 } //10 token::elevate
		$a_01_18 = {74 00 73 00 3a 00 3a 00 6c 00 6f 00 67 00 6f 00 6e 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //10 ts::logonpasswords
		$a_01_19 = {74 00 73 00 3a 00 3a 00 6d 00 73 00 74 00 73 00 63 00 } //10 ts::mstsc
		$a_01_20 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 73 00 61 00 6d 00 } //10 lsadump::sam
		$a_01_21 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 73 00 65 00 63 00 72 00 65 00 74 00 73 00 } //10 lsadump::secrets
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10+(#a_01_14  & 1)*10+(#a_01_15  & 1)*10+(#a_01_16  & 1)*10+(#a_01_17  & 1)*10+(#a_01_18  & 1)*10+(#a_01_19  & 1)*10+(#a_01_20  & 1)*10+(#a_01_21  & 1)*10) >=20
 
}