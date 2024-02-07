
rule Backdoor_Win32_MsxRat_dha{
	meta:
		description = "Backdoor:Win32/MsxRat!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 73 78 53 74 64 75 4f 6e 65 53 74 61 72 74 2e 63 6f 6d } //02 00  MsxStduOneStart.com
		$a_01_1 = {6d 73 78 52 41 54 31 2e 30 } //01 00  msxRAT1.0
		$a_01_2 = {6d 73 78 2e 65 78 65 } //00 00  msx.exe
		$a_01_3 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}