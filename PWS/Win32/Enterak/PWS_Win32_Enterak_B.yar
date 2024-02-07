
rule PWS_Win32_Enterak_B{
	meta:
		description = "PWS:Win32/Enterak.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 3f 75 70 3d 25 73 26 70 70 3d 25 73 26 73 73 70 3d 25 73 00 } //01 00  猥甿㵰猥瀦㵰猥猦灳┽s
		$a_01_1 = {26 70 5f 6d 6e 79 5f 62 61 6c 3d 00 } //01 00  瀦浟祮扟污=
		$a_01_2 = {68 6d 5f 70 5f 55 73 65 72 49 64 00 } //02 00  浨灟啟敳䥲d
		$a_01_3 = {66 3b c3 74 11 66 3d 06 00 74 0b 66 3d 05 00 74 05 bd 02 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}