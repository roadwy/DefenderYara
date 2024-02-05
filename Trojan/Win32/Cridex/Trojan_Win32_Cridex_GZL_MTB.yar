
rule Trojan_Win32_Cridex_GZL_MTB{
	meta:
		description = "Trojan:Win32/Cridex.GZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 34 24 8a 07 32 c2 0f b6 4f 90 01 01 32 ca e9 90 00 } //0a 00 
		$a_02_1 = {88 07 46 47 49 83 f9 90 01 01 0f 85 90 01 04 e9 90 01 04 ba 90 01 04 8a 06 32 c2 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}