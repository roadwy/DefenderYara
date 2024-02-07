
rule Trojan_BAT_FormBook_NC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 4c 00 4d 00 4b 00 4f 00 49 00 4a 00 4e 00 42 00 48 00 55 00 59 00 47 00 56 00 47 00 54 00 59 00 52 00 46 00 43 00 52 00 44 00 46 00 53 00 45 00 57 00 5a 00 58 00 } //01 00  PLMKOIJNBHUYGVGTYRFCRDFSEWZX
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //01 00  System.Reflection.Assembly
		$a_01_2 = {4c 00 78 00 78 00 78 00 61 00 64 00 } //01 00  Lxxxad
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 } //01 00  GetObject
		$a_01_5 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_6 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}