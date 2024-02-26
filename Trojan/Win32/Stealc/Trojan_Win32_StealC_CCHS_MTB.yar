
rule Trojan_Win32_StealC_CCHS_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 8d 04 3e 89 45 f4 03 55 e0 8b 45 f4 31 45 fc 31 55 fc 2b 5d fc 81 c6 90 01 04 ff 4d e8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}