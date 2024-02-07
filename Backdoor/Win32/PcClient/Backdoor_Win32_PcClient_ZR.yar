
rule Backdoor_Win32_PcClient_ZR{
	meta:
		description = "Backdoor:Win32/PcClient.ZR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_02_0 = {3d 00 00 20 03 73 90 01 01 6a 02 6a 00 6a 00 90 01 01 ff 15 90 00 } //02 00 
		$a_02_1 = {8a 14 01 80 f2 90 01 01 88 10 40 4d 75 f4 90 00 } //02 00 
		$a_02_2 = {6a 00 6a 00 6a 00 6a 00 6a 90 01 01 90 03 01 01 eb ff 90 00 } //01 00 
		$a_00_3 = {73 79 73 6c 6f 67 2e 64 61 74 } //01 00  syslog.dat
		$a_00_4 = {25 64 2e 62 61 6b } //01 00  %d.bak
		$a_00_5 = {25 32 64 25 32 64 25 32 64 25 32 64 25 32 64 25 32 64 } //01 00  %2d%2d%2d%2d%2d%2d
		$a_00_6 = {72 61 73 70 68 6f 6e 65 2e 70 62 6b } //00 00  rasphone.pbk
	condition:
		any of ($a_*)
 
}