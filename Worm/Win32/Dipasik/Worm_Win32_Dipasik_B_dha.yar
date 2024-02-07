
rule Worm_Win32_Dipasik_B_dha{
	meta:
		description = "Worm:Win32/Dipasik.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 5c 63 24 5c 77 69 6e 6e 74 5c 25 73 } //01 00  %s\c$\winnt\%s
		$a_00_1 = {25 73 5c 63 24 5c 77 69 6e 64 6f 77 73 5c 25 73 } //01 00  %s\c$\windows\%s
		$a_00_2 = {53 75 62 6a 65 63 74 3a 20 25 73 7c 25 73 7c 25 73 0d 0a 00 } //01 00 
		$a_00_3 = {3c 69 6e 66 6f 72 6d 61 74 69 6f 6e 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 3e } //01 00  <information@microsoft.com>
		$a_00_4 = {3c 6d 69 63 72 6f 73 6f 66 74 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 3e } //01 00  <microsoft@microsoft.com>
		$a_00_5 = {00 61 64 6d 69 6e 61 64 6d 69 6e 00 } //01 00  愀浤湩摡業n
		$a_00_6 = {00 61 64 6d 69 6e 31 32 33 34 00 } //01 00 
		$a_00_7 = {00 71 31 77 32 65 33 72 34 00 } //02 00  焀眱攲爳4
		$a_03_8 = {c4 0c 3c 34 74 04 3c 35 75 0a c7 05 90 01 04 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}