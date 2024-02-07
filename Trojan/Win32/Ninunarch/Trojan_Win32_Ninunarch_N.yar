
rule Trojan_Win32_Ninunarch_N{
	meta:
		description = "Trojan:Win32/Ninunarch.N,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 41 59 41 52 43 48 49 56 45 } //01 00  PAYARCHIVE
		$a_01_1 = {73 6d 73 61 64 64 69 6e 66 6f 3e } //01 00  smsaddinfo>
		$a_01_2 = {73 6d 73 6c 69 73 74 3e } //01 00  smslist>
		$a_01_3 = {73 6d 73 5f 63 6f 64 65 3e } //01 00  sms_code>
		$a_01_4 = {73 6d 73 5f 6e 75 6d 3e } //01 00  sms_num>
		$a_01_5 = {73 6d 73 5f 63 6f 73 74 3e } //01 00  sms_cost>
		$a_01_6 = {72 65 67 69 6f 6e 3e } //01 00  region>
		$a_01_7 = {63 6f 75 6e 74 72 79 3e } //01 00  country>
		$a_01_8 = {77 69 64 3e } //01 00  wid>
		$a_01_9 = {66 69 6c 65 69 64 3e } //00 00  fileid>
	condition:
		any of ($a_*)
 
}