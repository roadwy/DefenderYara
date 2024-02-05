
rule Trojan_BAT_Remcos_DOR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.DOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {fe 0c 02 00 20 01 00 00 00 58 20 00 00 00 00 fe 0e 02 00 45 0d 00 00 00 00 00 00 00 99 fe ff ff a8 fe ff ff ba fe ff ff cc fe ff ff db fe ff ff 05 ff ff ff 1d ff ff ff 2c ff ff ff 56 ff ff ff 8a ff ff ff 99 ff ff ff af ff ff ff dd 67 00 00 00 fe 0c 03 00 fe 0e 02 00 fe 0c 01 00 20 fe ff ff ff 3d 0a 00 00 00 20 01 00 00 00 38 04 00 00 00 fe 0c 01 00 45 02 00 00 00 00 00 00 00 7e ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}