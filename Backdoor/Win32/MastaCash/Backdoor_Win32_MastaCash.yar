
rule Backdoor_Win32_MastaCash{
	meta:
		description = "Backdoor:Win32/MastaCash,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {3c 44 69 61 6c 65 72 48 3e } //05 00  <DialerH>
		$a_01_1 = {4c 6f 61 64 65 72 58 57 61 69 74 57 69 6e 64 6f 77 } //05 00  LoaderXWaitWindow
		$a_01_2 = {50 72 65 66 69 78 00 } //03 00 
		$a_01_3 = {22 25 73 22 20 2d 44 58 25 75 20 2d 69 6d 6d 65 64 69 61 74 65 } //01 00  "%s" -DX%u -immediate
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 61 73 74 61 5c 44 69 61 6c 65 72 } //01 00  Software\Masta\Dialer
		$a_01_5 = {68 74 74 70 3a 2f 2f 6b 69 74 2e 6d 61 73 74 61 63 61 73 68 2e 63 6f 6d 2f } //01 00  http://kit.mastacash.com/
		$a_01_6 = {68 74 74 70 3a 2f 2f 64 78 2e 6d 61 73 74 61 63 61 73 68 2e 63 6f 6d } //01 00  http://dx.mastacash.com
		$a_01_7 = {64 69 61 6c 78 2e 65 78 65 } //00 00  dialx.exe
	condition:
		any of ($a_*)
 
}