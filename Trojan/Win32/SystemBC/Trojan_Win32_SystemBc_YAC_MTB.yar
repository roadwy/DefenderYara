
rule Trojan_Win32_SystemBc_YAC_MTB{
	meta:
		description = "Trojan:Win32/SystemBc.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 cc 03 55 ac 03 55 e8 2b d0 8b 45 d8 31 10 83 45 90 01 01 04 83 45 d8 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}