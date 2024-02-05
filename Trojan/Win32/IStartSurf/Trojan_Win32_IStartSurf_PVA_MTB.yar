
rule Trojan_Win32_IStartSurf_PVA_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f be 08 8b 45 90 01 01 33 d2 f7 75 90 01 01 0f be 84 15 90 01 01 ff ff ff 33 c8 8b 45 90 01 01 03 45 90 01 01 88 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}