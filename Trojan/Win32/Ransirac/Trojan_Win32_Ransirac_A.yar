
rule Trojan_Win32_Ransirac_A{
	meta:
		description = "Trojan:Win32/Ransirac.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {6c 61 6e 64 69 6e 67 2e 71 70 6f 65 2e 63 6f 6d 3a 38 30 38 30 2f 70 6f 70 6b 61 2f 3f 75 3d 36 26 69 64 3d } //02 00  landing.qpoe.com:8080/popka/?u=6&id=
		$a_01_1 = {4c 6f 63 6b 57 69 6e 64 6f 77 73 42 6f 74 5c 50 72 6f 6a 65 63 74 5c 41 6e 74 69 50 69 72 61 74 65 } //02 00  LockWindowsBot\Project\AntiPirate
		$a_01_2 = {77 69 6e 6c 6f 63 6b 5c 41 6e 74 69 50 69 72 61 74 65 5c 52 65 6c 65 61 73 65 } //02 00  winlock\AntiPirate\Release
		$a_01_3 = {49 6e 65 74 41 63 63 65 6c 65 72 61 74 6f 72 5c 49 6e 65 74 41 63 63 65 6c 65 72 61 74 6f 72 2e 65 78 65 } //02 00  InetAccelerator\InetAccelerator.exe
		$a_01_4 = {64 65 6c 65 74 65 20 48 4b 4c 4d 5c 53 79 73 74 65 6d 5c 43 75 72 72 } //01 00  delete HKLM\System\Curr
		$a_01_5 = {41 48 72 65 66 47 6f 54 6f 59 6f 75 72 73 65 6c 66 } //00 00  AHrefGoToYourself
	condition:
		any of ($a_*)
 
}