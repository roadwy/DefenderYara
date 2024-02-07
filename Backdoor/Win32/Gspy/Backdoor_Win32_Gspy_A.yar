
rule Backdoor_Win32_Gspy_A{
	meta:
		description = "Backdoor:Win32/Gspy.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {4f 00 57 00 4e 00 2d 00 42 00 4f 00 54 00 2d 00 49 00 44 00 } //02 00  OWN-BOT-ID
		$a_01_1 = {50 52 5f 57 72 69 74 65 } //02 00  PR_Write
		$a_00_2 = {69 6e 6a 65 63 74 6f 72 } //01 00  injector
		$a_00_3 = {73 63 72 65 65 6e 73 68 6f 74 } //00 00  screenshot
	condition:
		any of ($a_*)
 
}