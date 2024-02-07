
rule PWS_Win32_Steam_F{
	meta:
		description = "PWS:Win32/Steam.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 65 61 6d 63 72 61 63 6b } //01 00  steamcrack
		$a_01_1 = {53 74 65 61 6d 20 47 61 6d 65 20 43 72 61 63 6b 65 72 } //01 00  Steam Game Cracker
		$a_01_2 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 53 00 74 00 65 00 61 00 6d 00 20 00 50 00 68 00 69 00 73 00 68 00 69 00 6e 00 67 00 } //01 00  Desktop\Steam Phishing
		$a_01_3 = {43 00 72 00 61 00 63 00 6b 00 65 00 64 00 5f 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 49 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //00 00  Cracked_Account_Info.txt
	condition:
		any of ($a_*)
 
}