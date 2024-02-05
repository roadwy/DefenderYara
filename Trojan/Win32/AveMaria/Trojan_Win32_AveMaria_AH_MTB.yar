
rule Trojan_Win32_AveMaria_AH_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 bd 64 ff ff ff 89 95 58 ff ff ff 81 bd 5c ff ff ff 00 00 00 01 74 2a 8b 95 7c ff ff ff 03 95 5c ff ff ff 0f be 02 8b 8d 58 ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 5c ff ff ff 88 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}