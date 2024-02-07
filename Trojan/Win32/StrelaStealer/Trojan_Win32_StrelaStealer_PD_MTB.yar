
rule Trojan_Win32_StrelaStealer_PD_MTB{
	meta:
		description = "Trojan:Win32/StrelaStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 4d 8d 40 01 8b c3 ff c3 41 f7 f1 0f b6 0c 2a 41 30 48 90 01 01 3b de 72 90 00 } //01 00 
		$a_01_1 = {50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //01 00  Profiles\Outlook
		$a_01_2 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //01 00  IMAP Password
		$a_01_3 = {54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //01 00  Thunderbird\Profiles
		$a_01_4 = {73 74 72 65 6c 61 } //00 00  strela
		$a_00_5 = {5d 04 00 00 } //43 98 
	condition:
		any of ($a_*)
 
}