
rule Trojan_BAT_Remcos_MI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 5f 57 61 72 73 5f 54 68 65 5f 45 6d 70 69 72 65 5f 53 74 72 69 6b 65 73 5f 42 61 63 6b 5f 69 63 6f 6e } //1 Star_Wars_The_Empire_Strikes_Back_icon
		$a_01_1 = {58 43 43 56 56 } //1 XCCVV
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}