
rule VirTool_BAT_Utlaz_C_MTB{
	meta:
		description = "VirTool:BAT/Utlaz.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 43 75 72 72 65 6e 74 49 6d 70 6c 61 6e 74 } //1 get_CurrentImplant
		$a_81_1 = {49 6d 70 6c 61 6e 74 4c 69 73 74 } //1 ImplantList
		$a_81_2 = {2e 55 74 69 6c 73 2e 49 6d 70 6c 61 6e 74 55 74 69 6c 73 } //1 .Utils.ImplantUtils
		$a_81_3 = {55 74 69 6c 73 2e 43 6c 69 65 6e 74 55 74 69 6c 73 } //1 Utils.ClientUtils
		$a_81_4 = {41 74 6c 61 73 45 78 63 65 70 74 69 6f 6e } //1 AtlasException
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}