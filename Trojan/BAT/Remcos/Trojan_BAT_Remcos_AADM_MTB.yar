
rule Trojan_BAT_Remcos_AADM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 52 4d 30 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 CRM02.Properties.Resources.resources
		$a_01_1 = {43 52 4d 30 32 2e 50 72 6f 70 65 72 74 69 65 73 } //1 CRM02.Properties
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}