
rule Trojan_Win32_AveMaria_BK_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 90 03 45 9c 0f be 08 8b 95 6c ff ff ff 0f be 44 15 a8 33 c8 8b 55 90 03 55 9c 88 0a eb } //00 00 
	condition:
		any of ($a_*)
 
}