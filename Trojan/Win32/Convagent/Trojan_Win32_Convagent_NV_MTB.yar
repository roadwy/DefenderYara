
rule Trojan_Win32_Convagent_NV_MTB{
	meta:
		description = "Trojan:Win32/Convagent.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 58 89 c9 e8 90 01 04 31 07 68 90 01 04 5b 01 c9 81 c7 90 01 04 01 c9 68 90 01 04 59 39 f7 75 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}