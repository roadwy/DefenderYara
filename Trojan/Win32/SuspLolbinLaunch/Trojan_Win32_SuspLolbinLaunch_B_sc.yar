
rule Trojan_Win32_SuspLolbinLaunch_B_sc{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.B!sc,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 90 02 50 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00 90 00 } //02 00 
		$a_02_1 = {73 00 63 00 2e 00 65 00 78 00 65 00 90 02 50 63 00 6f 00 6e 00 66 00 69 00 67 00 90 02 50 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00 90 00 } //f6 ff 
		$a_00_2 = {71 00 75 00 65 00 72 00 79 00 } //f6 ff 
		$a_00_3 = {61 00 69 00 72 00 6c 00 6f 00 63 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}