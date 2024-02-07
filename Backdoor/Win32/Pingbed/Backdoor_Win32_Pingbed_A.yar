
rule Backdoor_Win32_Pingbed_A{
	meta:
		description = "Backdoor:Win32/Pingbed.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 ff 0f 1f 00 ff 15 90 01 04 8b f8 85 ff 74 90 01 01 6a 00 57 ff 15 90 01 04 8b d8 85 db 75 90 01 01 68 f4 01 00 00 ff 15 90 00 } //02 00 
		$a_03_1 = {68 fb 1f 00 00 50 ff 75 90 01 01 ff 15 90 01 04 83 7d 90 01 01 00 74 90 00 } //01 00 
		$a_01_2 = {25 73 20 25 73 00 } //01 00  猥┠s
		$a_00_3 = {4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 20 25 73 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}