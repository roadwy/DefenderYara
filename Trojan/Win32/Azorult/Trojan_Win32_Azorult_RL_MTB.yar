
rule Trojan_Win32_Azorult_RL_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {32 c2 88 01 c3 8d 40 00 55 8b ec 51 53 56 57 6a 90 01 01 68 90 01 04 68 90 01 04 6a 90 01 01 e8 90 01 04 89 45 90 01 01 8b 7d 90 01 01 be 90 01 04 bb 90 01 04 8b cf b2 90 01 01 8a 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}