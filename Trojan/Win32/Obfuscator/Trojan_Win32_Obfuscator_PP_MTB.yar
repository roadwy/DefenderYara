
rule Trojan_Win32_Obfuscator_PP_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 31 b8 90 01 04 83 f0 90 01 01 83 6d 74 90 01 01 83 7d 74 90 01 01 90 01 06 5e 83 c5 90 01 01 c9 c3 55 8b ec 83 ec 90 01 01 56 be 90 01 04 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}