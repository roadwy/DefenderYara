
rule Trojan_BAT_Vidar_NVC_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {1f 0a 8d 02 00 00 01 25 0a 06 16 20 90 01 03 1a 20 90 01 03 1a 61 9d 06 17 20 90 01 03 6c 20 90 01 03 6c 61 9d 06 18 20 90 01 03 3e 20 90 01 03 3e 61 9d 90 00 } //01 00 
		$a_01_1 = {54 00 61 00 75 00 74 00 65 00 6e 00 73 00 57 00 6d 00 6b 00 } //00 00  TautensWmk
	condition:
		any of ($a_*)
 
}