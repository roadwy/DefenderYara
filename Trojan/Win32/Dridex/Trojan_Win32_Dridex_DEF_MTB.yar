
rule Trojan_Win32_Dridex_DEF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b da b9 fb ff ff ff 2b de 83 eb 05 66 89 1d 90 01 04 8b 44 24 10 8b 74 24 14 05 90 01 04 89 44 24 10 a3 90 01 04 89 0d 90 01 04 89 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}