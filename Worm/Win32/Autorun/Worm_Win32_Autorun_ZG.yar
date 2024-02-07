
rule Worm_Win32_Autorun_ZG{
	meta:
		description = "Worm:Win32/Autorun.ZG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {75 73 62 73 70 72 65 61 64 } //02 00  usbspread
		$a_00_1 = {61 6e 74 69 7a 6f 6e 65 61 6c 61 72 6d } //02 00  antizonealarm
		$a_00_2 = {61 6e 74 69 73 61 6e 64 62 6f 78 69 65 } //02 00  antisandboxie
		$a_01_3 = {67 65 74 5f 46 69 72 65 50 61 73 73 77 6f 72 64 } //02 00  get_FirePassword
		$a_01_4 = {41 6e 74 69 50 61 72 61 6c 6c 65 6c 73 44 65 73 6b 74 6f 70 } //00 00  AntiParallelsDesktop
	condition:
		any of ($a_*)
 
}