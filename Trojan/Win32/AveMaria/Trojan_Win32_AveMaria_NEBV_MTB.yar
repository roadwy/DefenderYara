
rule Trojan_Win32_AveMaria_NEBV_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c7 6a 64 59 f7 f1 8b 8d 08 fc ff ff 8a 84 15 14 fc ff ff 30 04 0f 47 81 ff 00 d0 07 00 7c ce } //00 00 
	condition:
		any of ($a_*)
 
}