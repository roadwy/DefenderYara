
rule Trojan_BAT_NjRat_NECH_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 09 8e b7 32 0c 20 93 00 00 00 13 04 38 bb 53 ff ff 20 b7 00 00 00 2b f2 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 14 14 6f 90 01 01 00 00 0a 26 2a 90 00 } //02 00 
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //02 00  GetExecutingAssembly
		$a_01_2 = {43 4c 41 53 53 45 4b 5f 54 45 41 4d } //00 00  CLASSEK_TEAM
	condition:
		any of ($a_*)
 
}