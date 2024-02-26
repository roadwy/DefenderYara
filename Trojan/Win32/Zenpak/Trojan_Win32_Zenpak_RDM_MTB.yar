
rule Trojan_Win32_Zenpak_RDM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 } //00 00 
	condition:
		any of ($a_*)
 
}