
rule Trojan_Win32_GCleaner_BN_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 68 28 db 46 00 ff 15 e0 b0 46 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}