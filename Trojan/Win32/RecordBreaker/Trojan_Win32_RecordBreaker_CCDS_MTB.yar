
rule Trojan_Win32_RecordBreaker_CCDS_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.CCDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 08 83 f2 ?? 88 14 08 31 c0 c7 04 24 ?? ?? ?? ?? c7 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}