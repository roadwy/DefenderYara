
rule Trojan_Win32_Dridex_DEC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d6 2b d1 03 ea 8b 54 24 90 01 01 83 44 24 90 01 02 05 90 01 04 89 02 a3 90 01 04 0f b7 c5 6b c0 2d ba 4c 00 00 00 2b d0 2b d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}