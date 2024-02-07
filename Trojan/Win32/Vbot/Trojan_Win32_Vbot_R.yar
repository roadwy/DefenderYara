
rule Trojan_Win32_Vbot_R{
	meta:
		description = "Trojan:Win32/Vbot.R,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 7b 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 4c 00 65 00 76 00 65 00 6c 00 3d 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 65 00 7d 00 21 00 } //01 00  winmgmts:{impersonationLevel=impersonate}!
		$a_01_1 = {64 00 77 00 6f 00 6e 00 65 00 62 00 6c 00 61 00 63 00 6b 00 2e 00 64 00 61 00 74 00 } //01 00  dwoneblack.dat
		$a_01_2 = {5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 5c 00 50 00 68 00 61 00 72 00 6d 00 20 00 56 00 42 00 } //00 00  \Downloads\Pharm VB
	condition:
		any of ($a_*)
 
}