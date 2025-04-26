
rule PWS_Win32_OnLineGames_ZEA_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZEA!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 f9 f7 74 05 80 f9 f6 75 12 a8 38 75 0e f6 c1 01 74 08 f6 c5 01 75 02 46 46 46 46 8b d0 24 07 f6 c2 c0 } //1
		$a_01_1 = {c6 45 e4 31 c6 45 e5 32 c6 45 e6 31 c6 45 e7 2e c6 45 e8 31 c6 45 e9 32 c6 45 ea 2e c6 45 eb 31 c6 45 ec 37 c6 45 ed 30 c6 45 ee 2e c6 45 ef 31 c6 45 f0 38 c6 45 f1 34 } //1
		$a_01_2 = {2f 74 2e 61 73 70 } //1 /t.asp
		$a_01_3 = {43 3a 5c 6d 78 64 6f 73 2e 73 79 73 } //1 C:\mxdos.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}