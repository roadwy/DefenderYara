
rule Trojan_Win32_TinRat_A{
	meta:
		description = "Trojan:Win32/TinRat.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 69 6e 69 4d 65 74 49 2e 65 78 65 } //01 00  TiniMetI.exe
		$a_01_1 = {50 77 6d 53 76 63 2e 65 78 65 } //01 00  PwmSvc.exe
		$a_01_2 = {75 69 53 65 41 67 6e 74 2e 65 78 65 } //01 00  uiSeAgnt.exe
		$a_01_3 = {63 6f 72 65 53 65 72 76 69 63 65 53 68 65 6c 6c 2e 65 78 65 } //01 00  coreServiceShell.exe
		$a_01_4 = {50 74 53 65 73 73 69 6f 6e 41 67 65 6e 74 2e 65 78 65 } //00 00  PtSessionAgent.exe
	condition:
		any of ($a_*)
 
}