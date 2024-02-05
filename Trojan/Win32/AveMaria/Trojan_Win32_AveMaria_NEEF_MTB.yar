
rule Trojan_Win32_AveMaria_NEEF_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 95 7c ff ff ff 03 95 5c ff ff ff 0f be 02 8b 8d 58 ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 5c ff ff ff 88 01 eb 98 } //00 00 
	condition:
		any of ($a_*)
 
}