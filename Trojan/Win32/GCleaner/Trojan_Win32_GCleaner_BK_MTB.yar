
rule Trojan_Win32_GCleaner_BK_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 50 e8 90 01 01 3b 04 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}