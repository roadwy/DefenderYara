
rule Trojan_BAT_AgentTesla_NVK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {66 68 66 73 73 64 64 73 73 64 66 68 66 64 64 66 68 68 73 } //1 fhfssddssdfhfddfhhs
		$a_81_1 = {67 61 73 64 73 66 64 66 73 68 73 67 } //1 gasdsfdfshsg
		$a_81_2 = {73 64 64 64 64 66 66 73 68 68 64 6a 66 66 66 66 66 67 6a 73 6b 64 67 73 66 61 63 73 61 66 70 } //1 sddddffshhdjfffffgjskdgsfacsafp
		$a_81_3 = {6e 68 66 66 73 6b 64 73 6b 64 61 66 66 64 64 68 73 63 66 66 64 66 } //1 nhffskdskdaffddhscffdf
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_81_6 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}