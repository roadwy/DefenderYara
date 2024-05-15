
rule Worm_Win32_Vobfus_HNS_MTB{
	meta:
		description = "Worm:Win32/Vobfus.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {ea 77 a4 72 41 98 a4 72 07 05 a2 72 86 93 a3 72 f9 09 a3 72 ee 6a a4 72 37 05 a2 72 8d 72 a4 72 fd a0 94 72 31 68 a4 72 44 c2 a0 72 9b 6a a2 72 29 19 a2 72 62 72 a4 72 fa 56 a2 72 88 be a0 72 } //00 00 
	condition:
		any of ($a_*)
 
}