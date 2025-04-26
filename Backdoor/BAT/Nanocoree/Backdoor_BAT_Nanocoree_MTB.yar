
rule Backdoor_BAT_Nanocoree_MTB{
	meta:
		description = "Backdoor:BAT/Nanocoree!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 } //5 NanoCore
		$a_01_1 = {43 6c 69 65 6e 74 53 65 74 74 69 6e 67 43 68 61 6e 67 65 64 } //1 ClientSettingChanged
		$a_01_2 = {53 65 6e 64 54 6f 53 65 72 76 65 72 } //1 SendToServer
		$a_01_3 = {44 69 73 61 62 6c 65 50 72 6f 74 65 63 74 69 6f 6e } //1 DisableProtection
		$a_01_4 = {51 75 65 75 65 55 73 65 72 57 6f 72 6b 49 74 65 6d } //1 QueueUserWorkItem
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}