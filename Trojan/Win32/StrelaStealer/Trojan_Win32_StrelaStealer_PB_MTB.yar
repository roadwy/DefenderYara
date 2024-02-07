
rule Trojan_Win32_StrelaStealer_PB_MTB{
	meta:
		description = "Trojan:Win32/StrelaStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 f6 8a 82 90 01 03 00 30 44 0c 10 41 3b cf 90 00 } //01 00 
		$a_01_1 = {50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //01 00  Profiles\Outlook
		$a_01_2 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //01 00  IMAP Password
		$a_01_3 = {54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //01 00  Thunderbird\Profiles
		$a_01_4 = {73 74 72 65 6c 61 } //00 00  strela
	condition:
		any of ($a_*)
 
}