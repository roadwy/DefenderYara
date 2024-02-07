
rule Backdoor_Win32_Wudfok_A{
	meta:
		description = "Backdoor:Win32/Wudfok.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 69 6e 58 53 20 32 2e 30 20 64 65 6d 6f 6e } //03 00  WinXS 2.0 demon
		$a_01_1 = {5c 57 75 64 66 53 76 63 2e 65 78 65 } //02 00  \WudfSvc.exe
		$a_01_2 = {25 73 20 25 73 20 48 54 54 50 2f 25 64 2e 25 64 } //00 00  %s %s HTTP/%d.%d
	condition:
		any of ($a_*)
 
}