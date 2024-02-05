
rule Trojan_BAT_Nanocore_NEE_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {28 6a 00 00 0a 28 22 00 00 06 0b 07 28 24 00 00 06 28 2e 00 00 0a 0c 72 8c fb 03 70 28 6b 00 00 0a 6f 6c 00 00 0a 16 9a 14 } //05 00 
		$a_01_1 = {52 00 65 00 6c 00 69 00 67 00 69 00 6f 00 6e 00 5f 00 4a 00 65 00 6f 00 70 00 61 00 72 00 64 00 79 00 } //05 00 
		$a_01_2 = {6e 00 63 00 76 00 69 00 65 00 77 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}