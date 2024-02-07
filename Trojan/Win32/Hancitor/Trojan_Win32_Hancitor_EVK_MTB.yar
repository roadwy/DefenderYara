
rule Trojan_Win32_Hancitor_EVK_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.EVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 41 53 44 46 79 67 73 76 54 41 46 53 72 74 77 79 73 67 66 77 74 79 75 } //01 00  rASDFygsvTAFSrtwysgfwtyu
		$a_01_1 = {3f 1b c3 44 45 79 67 73 72 54 41 46 ac 8d 74 77 c1 73 67 66 77 74 79 75 40 72 41 53 44 46 79 67 73 76 54 41 46 53 72 74 77 79 73 67 66 77 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}