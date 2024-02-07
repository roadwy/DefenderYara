
rule Trojan_BAT_Netwire_MOR_MTB{
	meta:
		description = "Trojan:BAT/Netwire.MOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //07 00  FromBase64String
		$a_03_3 = {17 8d 59 00 00 01 25 16 1f 20 9d 28 90 01 03 0a 20 00 01 00 00 14 14 17 8d 10 00 00 01 25 16 02 a2 6f 90 01 03 0a 74 30 00 00 01 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}