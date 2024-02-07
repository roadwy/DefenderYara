
rule Trojan_BAT_AgentTesla_NTZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_80_0 = {42 65 67 69 6e 52 65 61 64 } //BeginRead  01 00 
		$a_80_1 = {40 53 79 73 74 65 6d 40 2e 40 52 65 66 6c 65 63 74 69 6f 6e 40 2e 40 41 73 73 65 6d 62 6c 79 40 } //@System@.@Reflection@.@Assembly@  01 00 
		$a_80_2 = {40 40 40 4c 6f 61 64 40 40 40 } //@@@Load@@@  01 00 
		$a_80_3 = {57 41 31 2e 52 65 73 6f 75 72 63 65 73 } //WA1.Resources  01 00 
		$a_80_4 = {41 73 53 73 4d 6d 42 } //AsSsMmB  01 00 
		$a_80_5 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //GetManifestResourceNames  01 00 
		$a_80_6 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_7 = {43 6f 6d 62 6f 42 6f 78 49 74 65 6d 31 } //ComboBoxItem1  01 00 
		$a_80_8 = {56 53 5f 56 45 52 53 49 4f 4e 5f 49 4e 46 4f } //VS_VERSION_INFO  01 00 
		$a_80_9 = {56 61 72 46 69 6c 65 49 6e 66 6f } //VarFileInfo  01 00 
		$a_80_10 = {53 74 72 69 6e 67 46 69 6c 65 49 6e 66 6f } //StringFileInfo  01 00 
		$a_81_11 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00  GetMethods
		$a_81_12 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}