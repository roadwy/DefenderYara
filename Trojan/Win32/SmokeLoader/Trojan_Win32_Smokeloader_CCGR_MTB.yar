
rule Trojan_Win32_Smokeloader_CCGR_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 14 8b 4c 24 10 30 04 0a 83 7d 0c } //00 00 
	condition:
		any of ($a_*)
 
}