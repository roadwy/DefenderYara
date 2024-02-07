
rule Trojan_Win32_Trickbot_SV_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.SV!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 53 54 52 5f 50 41 53 53 5f } //01 00  ESTR_PASS_
		$a_01_1 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37 } //01 00  abe2869f-9b47-4cd9-a358-c22904dba7f7
		$a_01_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5f 00 57 00 69 00 6e 00 49 00 6e 00 65 00 74 00 5f 00 2a 00 } //02 00  Microsoft_WinInet_*
		$a_01_3 = {62 52 53 38 79 59 51 30 41 50 71 39 78 66 7a 43 } //00 00  bRS8yYQ0APq9xfzC
	condition:
		any of ($a_*)
 
}