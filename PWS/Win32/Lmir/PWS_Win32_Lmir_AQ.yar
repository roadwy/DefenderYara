
rule PWS_Win32_Lmir_AQ{
	meta:
		description = "PWS:Win32/Lmir.AQ,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {67 65 74 68 6f 73 74 6e 61 6d 65 } //0a 00  gethostname
		$a_00_1 = {63 6c 6f 73 65 73 6f 63 6b 65 74 } //0a 00  closesocket
		$a_00_2 = {57 6f 6f 6f 6c 2e 64 61 74 } //0a 00  Woool.dat
		$a_00_3 = {54 54 72 6f 79 57 6f 6f 6f 6c } //0a 00  TTroyWoool
		$a_00_4 = {57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  WARE\Borland\Delphi
		$a_02_5 = {50 6a 20 e8 90 01 04 50 e8 90 01 04 85 c0 74 90 01 01 c7 44 90 01 02 01 00 00 00 8d 44 90 01 02 50 68 90 01 02 40 00 6a 00 e8 90 01 04 80 90 01 02 00 74 90 01 01 c7 44 90 01 02 02 00 00 00 90 00 } //01 00 
		$a_00_6 = {67 5f 55 73 65 72 50 77 64 41 64 64 72 3a } //01 00  g_UserPwdAddr:
		$a_00_7 = {77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //01 00  www.microsoft.com
		$a_00_8 = {5c 5c 6d 72 67 74 61 73 6b 32 } //01 00  \\mrgtask2
		$a_00_9 = {6d 61 70 5c 38 38 58 36 30 30 2e 6e 6d 70 } //00 00  map\88X600.nmp
	condition:
		any of ($a_*)
 
}