
rule Worm_Win32_RJump{
	meta:
		description = "Worm:Win32/RJump,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0d 9c 71 40 00 8b 15 a0 71 40 00 a1 a4 71 40 00 6a 05 } //01 00 
		$a_01_1 = {68 74 71 40 00 6a 00 ff d6 85 c0 74 09 } //00 00 
	condition:
		any of ($a_*)
 
}