
rule Trojan_BAT_Formbook_NUM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 65 67 69 6e 52 65 61 64 } //01 00  BeginRead
		$a_81_1 = {40 53 79 73 74 65 6d 40 2e 40 52 65 66 6c 65 63 74 69 6f 6e 40 2e 40 41 73 73 65 6d 62 6c 79 40 } //01 00  @System@.@Reflection@.@Assembly@
		$a_81_2 = {40 40 40 4c 6f 61 64 40 40 40 } //01 00  @@@Load@@@
		$a_81_3 = {57 41 31 2e 52 65 73 6f 75 72 63 65 73 } //01 00  WA1.Resources
		$a_81_4 = {41 73 53 73 4d 6d 42 } //01 00  AsSsMmB
		$a_81_5 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //01 00  GetManifestResourceNames
		$a_81_6 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_7 = {56 53 5f 56 45 52 53 49 4f 4e 5f 49 4e 46 4f } //01 00  VS_VERSION_INFO
		$a_81_8 = {56 61 72 46 69 6c 65 49 6e 66 6f } //01 00  VarFileInfo
		$a_81_9 = {53 74 72 69 6e 67 46 69 6c 65 49 6e 66 6f } //01 00  StringFileInfo
		$a_81_10 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}