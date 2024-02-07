
rule Trojan_Win32_Dinwod_SB_MSR{
	meta:
		description = "Trojan:Win32/Dinwod.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 32 69 68 73 66 61 2e 63 6f 6d } //05 00  www.2ihsfa.com
		$a_01_1 = {68 74 74 70 3a 2f 2f 68 66 75 69 65 33 32 2e 32 69 68 73 66 61 2e 63 6f 6d } //05 00  http://hfuie32.2ihsfa.com
		$a_01_2 = {68 74 74 70 3a 2f 2f 72 65 61 63 68 2e 63 70 2d 62 61 63 6b 2e 62 69 7a } //01 00  http://reach.cp-back.biz
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 69 00 77 00 71 00 67 00 67 00 74 00 66 00 5c 00 64 00 61 00 74 00 61 00 } //01 00  Software\iwqggtf\data
		$a_01_4 = {6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 62 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 } //01 00  manager/account_settings/account_billing
		$a_01_5 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //01 00  CryptUnprotectData
		$a_01_6 = {46 42 43 6f 6f 6b 69 65 73 2e 70 64 62 } //00 00  FBCookies.pdb
		$a_00_7 = {5d 04 00 00 b0 } //1a 04 
	condition:
		any of ($a_*)
 
}