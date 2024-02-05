
rule Trojan_Win32_Staser_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Staser.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5d 89 1c 24 bb 04 00 00 00 01 d8 5b 53 57 ff 74 24 04 5f 8f 04 24 57 ff 0c 24 5f 31 3c 24 33 3c 24 31 3c 24 5b e9 99 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}