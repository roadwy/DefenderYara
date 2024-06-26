
rule Worm_Win32_Autorun_NL{
	meta:
		description = "Worm:Win32/Autorun.NL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 64 41 75 64 69 6f } //01 00  HdAudio
		$a_00_1 = {5c 00 53 00 63 00 72 00 43 00 61 00 70 00 2e 00 6a 00 70 00 67 00 } //01 00  \ScrCap.jpg
		$a_00_2 = {54 00 43 00 50 00 3a 00 2a 00 3a 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 3a 00 } //01 00  TCP:*:Enabled:
		$a_00_3 = {5f 00 23 00 57 00 46 00 54 00 23 00 5f 00 00 00 16 00 00 00 24 00 46 00 43 00 52 00 43 00 65 00 72 00 72 00 6f 00 72 00 24 00 } //00 00 
	condition:
		any of ($a_*)
 
}