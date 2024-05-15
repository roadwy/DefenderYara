
rule Trojan_Win32_StealC_HR_MTB{
	meta:
		description = "Trojan:Win32/StealC.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 31 45 fc 8b 45 fc 89 45 90 01 01 89 75 f0 8b 45 90 01 01 89 45 f0 8b 45 f8 31 45 f0 8b 45 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}