
rule Trojan_Win32_CobaltStrike_QE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {48 6f 72 65 6b 47 6c 65 70 57 } //03 00  HorekGlepW
		$a_81_1 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //03 00  GetWindowThreadProcessId
		$a_81_2 = {53 65 74 54 69 6d 65 72 } //03 00  SetTimer
		$a_81_3 = {43 72 65 61 74 65 57 69 6e 64 6f 77 45 78 57 } //03 00  CreateWindowExW
		$a_81_4 = {50 6f 73 74 54 68 72 65 61 64 4d 65 73 73 61 67 65 57 } //03 00  PostThreadMessageW
		$a_81_5 = {50 6f 73 74 4d 65 73 73 61 67 65 57 } //03 00  PostMessageW
		$a_81_6 = {43 72 65 61 74 65 46 69 6c 65 41 } //00 00  CreateFileA
	condition:
		any of ($a_*)
 
}