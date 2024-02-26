
rule Trojan_Win32_RecordBreaker_CCDS_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.CCDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 08 83 f2 90 01 01 88 14 08 31 c0 c7 04 24 90 01 04 c7 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}