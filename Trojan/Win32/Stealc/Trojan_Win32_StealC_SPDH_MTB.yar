
rule Trojan_Win32_StealC_SPDH_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 31 45 f8 8b 45 f0 33 45 f8 2b d0 } //00 00 
	condition:
		any of ($a_*)
 
}