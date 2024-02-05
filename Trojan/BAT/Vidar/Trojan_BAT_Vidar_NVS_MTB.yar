
rule Trojan_BAT_Vidar_NVS_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 26 00 00 0a 0c 73 90 01 01 00 00 0a 0d 09 07 6f 90 01 01 00 00 0a 13 04 08 11 04 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {44 42 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00 
		$a_01_2 = {52 61 77 5a 69 70 41 6e 64 41 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}