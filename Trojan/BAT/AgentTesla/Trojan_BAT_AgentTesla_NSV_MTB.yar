
rule Trojan_BAT_AgentTesla_NSV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 55 30 6d 78 68 38 6e 53 4f 73 6d 4a 44 57 5a 48 6a 2e 4d 72 6a 53 67 37 4b 52 38 30 46 34 66 63 72 47 66 34 } //CU0mxh8nSOsmJDWZHj.MrjSg7KR80F4fcrGf4  1
		$a_80_1 = {35 53 33 5a 35 43 32 48 35 34 38 39 52 46 45 37 38 35 35 5a 38 48 } //5S3Z5C2H5489RFE7855Z8H  1
		$a_80_2 = {55 6e 64 65 72 6c 79 69 6e 67 53 79 73 74 65 6d 54 79 70 65 } //UnderlyingSystemType  1
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}