
rule Backdoor_Win32_Loony{
	meta:
		description = "Backdoor:Win32/Loony,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 20 63 6c 6f 6e 65 73 20 74 6f 20 25 73 20 6f 6e 20 70 6f 72 74 20 25 73 } //02 00  %s clones to %s on port %s
		$a_01_1 = {6e 74 56 65 72 73 69 6f 6e 5c 00 79 61 68 6f 6f 20 4d 65 73 73 65 6e } //02 00 
		$a_01_2 = {6b 69 6c 6c 74 68 72 65 61 64 00 70 61 73 73 77 6f 72 64 73 00 6b 65 79 73 00 } //02 00  楫汬桴敲摡瀀獡睳牯獤欀祥s
		$a_01_3 = {73 79 6e 00 73 6f 63 6b 73 34 00 6c 6f 61 } //02 00  祳n潳正㑳氀慯
		$a_01_4 = {6e 77 6e 63 64 6b 65 79 2e 69 6e 69 00 25 73 5c 25 73 } //00 00  睮据此祥椮楮─屳猥
	condition:
		any of ($a_*)
 
}