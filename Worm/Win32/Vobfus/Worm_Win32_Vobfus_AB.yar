
rule Worm_Win32_Vobfus_AB{
	meta:
		description = "Worm:Win32/Vobfus.AB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {1b ce 00 2a 23 90 01 02 1b cf 00 2a 23 90 01 02 1b d0 00 2a 23 90 01 02 1b d1 00 2a 23 90 01 02 1b ce 00 2a 23 90 01 02 1b cf 00 2a 23 90 01 02 1b d2 00 2a 23 90 01 02 1b d3 00 2a 23 90 01 02 1b d4 00 2a 23 90 01 02 1b d2 00 2a 23 90 01 02 1b d1 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}