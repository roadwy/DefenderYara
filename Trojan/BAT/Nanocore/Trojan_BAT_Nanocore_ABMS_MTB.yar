
rule Trojan_BAT_Nanocore_ABMS_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}