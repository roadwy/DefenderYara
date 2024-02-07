
rule Trojan_BAT_AgentTesla_NXL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 37 32 62 34 38 61 32 32 2d 32 37 34 62 2d 34 32 61 62 2d 62 31 64 63 2d 65 62 32 35 33 61 37 38 39 36 31 63 } //01 00  $72b48a22-274b-42ab-b1dc-eb253a78961c
		$a_01_1 = {53 65 74 53 70 72 69 74 65 } //01 00  SetSprite
		$a_01_2 = {50 61 72 73 65 46 61 69 6c 75 72 65 } //01 00  ParseFailure
		$a_01_3 = {53 74 72 75 63 74 75 72 61 6c 45 71 75 61 6c 69 74 79 43 6f 6d 70 61 72 65 72 } //01 00  StructuralEqualityComparer
		$a_01_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NXL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 07 11 07 2c 40 11 04 1f 21 8c 90 01 01 00 00 01 09 1f 0e 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 1f 5e 90 00 } //01 00 
		$a_81_1 = {43 6f 6d 70 61 72 65 4f 62 6a 65 63 74 47 72 65 61 74 65 72 45 71 75 61 6c } //01 00  CompareObjectGreaterEqual
		$a_81_2 = {51 75 65 73 74 4b 69 6e 67 64 6f 6d 2e 57 6f 72 6b 65 72 48 65 6c 70 65 72 } //01 00  QuestKingdom.WorkerHelper
		$a_81_3 = {51 51 51 30 30 } //01 00  QQQ00
		$a_81_4 = {43 6f 6e 63 61 74 65 6e 61 74 65 4f 62 6a 65 63 74 } //01 00  ConcatenateObject
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_6 = {00 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 00 } //01 00  䤀䥉䥉䥉䥉䥉䥉䥉䥉䥉䥉I
		$a_81_7 = {4f 49 4b 4d 4e 4a 55 59 48 42 56 47 54 30 31 } //00 00  OIKMNJUYHBVGT01
	condition:
		any of ($a_*)
 
}