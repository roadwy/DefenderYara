
rule Trojan_Win32_CobaltStrike_GC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 89 c8 bb 15 00 00 00 f7 f3 0f b6 81 00 f0 60 00 0f b6 9a c4 03 56 00 31 d8 88 81 00 f0 60 00 41 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}