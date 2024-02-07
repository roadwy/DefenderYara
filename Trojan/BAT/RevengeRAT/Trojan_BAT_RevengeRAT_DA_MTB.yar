
rule Trojan_BAT_RevengeRAT_DA_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 37 65 31 61 61 36 30 32 2d 31 36 64 63 2d 34 35 31 61 2d 38 65 35 34 2d 31 37 63 39 66 39 35 39 61 31 39 63 } //01 00  $7e1aa602-16dc-451a-8e54-17c9f959a19c
		$a_81_1 = {49 6d 70 72 6f 76 50 6f 73 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  ImprovPose.Properties.Resources
		$a_81_2 = {74 65 6e 73 6f 72 66 6c 6f 77 2e 6f 72 67 2f 64 6f 63 73 } //01 00  tensorflow.org/docs
		$a_81_3 = {54 72 61 69 6e 20 6d 6f 64 65 6c } //01 00  Train model
		$a_81_4 = {54 72 79 50 61 72 73 65 } //01 00  TryParse
		$a_81_5 = {43 6c 6f 6e 65 } //01 00  Clone
		$a_81_6 = {44 69 63 74 69 6f 6e 61 72 79 45 6e 74 72 79 } //00 00  DictionaryEntry
	condition:
		any of ($a_*)
 
}