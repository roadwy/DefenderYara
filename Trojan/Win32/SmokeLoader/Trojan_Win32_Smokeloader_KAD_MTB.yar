
rule Trojan_Win32_Smokeloader_KAD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {6c 65 74 65 62 6f 76 75 6c 61 20 6a 69 6e } //letebovula jin  01 00 
		$a_80_1 = {46 65 77 69 78 65 74 6f 6d 6f 6e 65 6c 6f } //Fewixetomonelo  01 00 
		$a_80_2 = {7a 65 7a 6f 74 65 6b 6f } //zezoteko  00 00 
	condition:
		any of ($a_*)
 
}