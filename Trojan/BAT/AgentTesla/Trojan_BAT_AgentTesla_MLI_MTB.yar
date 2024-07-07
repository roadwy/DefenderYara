
rule Trojan_BAT_AgentTesla_MLI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_80_0 = {53 69 67 6e 61 74 75 72 65 44 65 66 6f 72 6d 61 74 74 65 72 2e 49 50 65 72 6d 69 73 73 69 6f 6e } //SignatureDeformatter.IPermission  1
		$a_80_1 = {43 6f 6e 64 69 74 69 6f 6e 61 6c 57 65 61 6b 54 61 62 6c 65 } //ConditionalWeakTable  1
		$a_80_2 = {55 6e 6d 61 6e 61 67 65 64 46 75 6e 63 74 69 6f 6e } //UnmanagedFunction  1
		$a_80_3 = {44 6f 6d 61 69 6e 50 6f 6c 69 63 79 } //DomainPolicy  1
		$a_80_4 = {42 69 74 6d 61 70 } //Bitmap  1
		$a_80_5 = {4c 6f 63 6b 48 6f 6c 64 65 72 } //LockHolder  1
		$a_80_6 = {55 49 6e 74 50 74 72 } //UIntPtr  1
		$a_80_7 = {50 6f 69 6e 74 65 72 41 74 74 72 69 62 75 74 65 } //PointerAttribute  1
		$a_80_8 = {50 61 74 68 6f 6c 6f 67 79 } //Pathology  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=8
 
}