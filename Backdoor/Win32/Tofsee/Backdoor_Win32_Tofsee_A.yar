
rule Backdoor_Win32_Tofsee_A{
	meta:
		description = "Backdoor:Win32/Tofsee.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 53 65 74 75 70 } //01 00  CurrentVersion\WinSetup
		$a_01_1 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 25 73 } //02 00  Referer: http://%s%s
		$a_01_2 = {7b 64 69 73 70 6c 61 79 3a 6e 6f 6e 65 7d } //01 00  {display:none}
		$a_00_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 } //01 00  http://%s:%d/%s
		$a_00_4 = {5f 5f 52 52 5f 42 4f 54 5f 5f } //02 00  __RR_BOT__
		$a_00_5 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 25 73 20 65 6e 61 62 6c 65 } //02 00  netsh firewall set allowedprogram %s enable
		$a_01_6 = {81 7c 24 24 aa aa aa aa 59 59 } //02 00 
		$a_01_7 = {6f 6d 61 69 6e 3d 00 00 0d 0a 4c 6f 63 61 74 69 } //00 00 
	condition:
		any of ($a_*)
 
}