
rule Trojan_Win32_Zusy_RG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 65 fc 00 8b c6 8a 96 90 01 03 00 83 e0 03 6a 00 88 55 bf 8a 88 90 01 03 00 32 ca 8d 04 11 88 86 90 01 03 00 e8 90 01 04 8a 45 bf 28 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}