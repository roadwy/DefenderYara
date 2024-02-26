
rule Trojan_Win32_RecordBreaker_EM_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 e8 80 03 f0 89 75 f8 8d 04 36 50 6a 40 } //01 00 
		$a_81_1 = {57 54 4d 52 5f } //01 00  WTMR_
		$a_81_2 = {53 4d 50 48 52 5f } //01 00  SMPHR_
		$a_81_3 = {77 61 6c 6c 65 74 73 } //01 00  wallets
		$a_81_4 = {77 6c 74 73 5f } //01 00  wlts_
		$a_81_5 = {73 63 72 6e 73 68 74 5f } //01 00  scrnsht_
		$a_81_6 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6f 62 6a 65 63 74 } //01 00  Content-Type: application/x-object
		$a_81_7 = {61 75 74 6f 66 69 6c 6c 2e 74 78 74 } //01 00  autofill.txt
		$a_81_8 = {63 6f 6f 6b 69 65 73 2e 74 78 74 } //00 00  cookies.txt
	condition:
		any of ($a_*)
 
}