
rule Trojan_Win32_StealC_OPT_MTB{
	meta:
		description = "Trojan:Win32/StealC.OPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 03 45 90 01 01 89 45 f8 8b 45 90 01 01 31 45 fc 8b 45 fc 89 45 90 01 01 89 75 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 f8 31 45 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}