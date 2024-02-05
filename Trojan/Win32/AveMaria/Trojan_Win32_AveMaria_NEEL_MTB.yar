
rule Trojan_Win32_AveMaria_NEEL_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f be 44 15 84 33 c8 8b 95 7c ff ff ff 03 95 50 ff ff ff 88 0a eb 98 } //00 00 
	condition:
		any of ($a_*)
 
}