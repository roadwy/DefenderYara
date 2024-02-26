
rule Trojan_Win32_Swisyn_GNF_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 66 47 73 45 41 31 23 } //01 00  rfGsEA1#
		$a_01_1 = {40 4d 76 24 65 77 2f 31 } //01 00  @Mv$ew/1
		$a_01_2 = {77 61 3f 6b 34 67 32 61 } //01 00  wa?k4g2a
		$a_01_3 = {71 66 78 72 6e 53 6b 42 4e 6b 6a } //00 00  qfxrnSkBNkj
	condition:
		any of ($a_*)
 
}