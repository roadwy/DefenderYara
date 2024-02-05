
rule Trojan_BAT_AgentTesla_NNM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 68 73 2e 72 65 66 73 6e 61 72 74 2f 2f 3a 73 70 74 74 68 } ///hs.refsnart//:sptth  01 00 
		$a_80_1 = {6d 61 6b 65 66 69 6c 2e 46 72 65 6e 63 } //makefil.Frenc  01 00 
		$a_80_2 = {50 50 6f 6f 73 65 67 65 32 32 32 32 32 66 77 72 77 65 66 77 65 } //PPoosege22222fwrwefwe  01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00 
		$a_01_5 = {47 46 46 51 46 46 44 53 46 57 51 46 57 51 46 57 51 } //01 00 
		$a_01_6 = {47 46 46 51 46 57 51 46 57 51 46 57 51 } //00 00 
	condition:
		any of ($a_*)
 
}