
rule Trojan_Win32_Suspfsiutil_A_ibt{
	meta:
		description = "Trojan:Win32/Suspfsiutil.A!ibt,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {66 00 73 00 75 00 74 00 69 00 6c 00 90 02 10 73 00 65 00 74 00 7a 00 65 00 72 00 6f 00 64 00 61 00 74 00 61 00 90 00 } //02 00 
		$a_02_1 = {6f 00 66 00 66 00 73 00 65 00 74 00 3d 00 30 00 90 02 05 6c 00 65 00 6e 00 67 00 74 00 68 00 3d 00 35 00 32 00 34 00 32 00 38 00 38 00 90 00 } //02 00 
		$a_00_2 = {64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 } //00 00  del /f /q
	condition:
		any of ($a_*)
 
}