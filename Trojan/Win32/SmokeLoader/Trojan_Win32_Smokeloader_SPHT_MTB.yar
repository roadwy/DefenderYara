
rule Trojan_Win32_Smokeloader_SPHT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 89 45 f8 8b 4d fc 33 4d f0 8b 45 f8 03 45 cc 33 c1 89 4d fc } //00 00 
	condition:
		any of ($a_*)
 
}