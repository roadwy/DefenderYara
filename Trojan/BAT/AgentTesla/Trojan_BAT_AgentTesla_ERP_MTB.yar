
rule Trojan_BAT_AgentTesla_ERP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {0d 59 8e 7f 3d 4e 8e 7f 0d 59 8e 7f 0d 59 36 52 0d 59 } //01 00 
		$a_01_1 = {49 00 33 06 6e 00 76 00 33 06 6f 00 6b 00 33 06 65 00 } //01 00  Iسnvسokسe
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_4 = {69 00 66 00 75 00 5f 00 54 00 } //00 00  ifu_T
	condition:
		any of ($a_*)
 
}