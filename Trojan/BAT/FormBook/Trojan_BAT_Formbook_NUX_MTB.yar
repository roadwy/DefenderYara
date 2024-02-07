
rule Trojan_BAT_Formbook_NUX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 bf b6 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 fc 00 00 00 41 00 00 00 30 01 00 00 } //01 00 
		$a_01_1 = {24 61 62 32 38 37 32 30 35 2d 32 63 63 65 2d 34 64 35 36 2d 39 62 36 66 2d 62 30 36 63 65 32 38 61 33 31 64 37 } //01 00  $ab287205-2cce-4d56-9b6f-b06ce28a31d7
		$a_01_2 = {54 00 69 00 6d 00 65 00 55 00 74 00 69 00 6c 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 } //01 00  TimeUtils.Properties
		$a_01_3 = {47 00 65 00 74 00 44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 46 00 6f 00 72 00 46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 69 00 6e 00 74 00 65 00 72 00 } //00 00  GetDelegateForFunctionPointer
	condition:
		any of ($a_*)
 
}