
rule Trojan_BAT_AgentTesla_RAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 69 61 6c 69 7a 65 43 6f 6d 70 6f 6e 65 6e 74 } //1 InitializeComponent
		$a_01_1 = {58 35 30 39 43 6f 6e 73 74 61 6e 74 73 } //1 X509Constants
		$a_01_2 = {46 6f 72 6d 5f 68 61 73 68 46 75 6e 63 74 69 6f 6e 73 } //1 Form_hashFunctions
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {49 53 75 70 70 6f 72 74 49 6e 69 74 69 61 6c 69 7a 65 } //1 ISupportInitialize
		$a_01_5 = {6d 5f 61 69 48 61 73 68 65 73 } //1 m_aiHashes
		$a_00_6 = {53 00 65 00 6c 00 65 00 63 00 74 00 6f 00 72 00 58 00 } //1 SelectorX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_RAA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 9f a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 7e 00 00 00 38 00 00 00 cf 00 00 00 20 01 00 00 01 01 00 00 01 00 00 00 3a 01 00 00 1c 00 00 00 5a 00 00 00 02 00 00 00 5f 00 00 00 12 00 00 00 38 00 00 00 46 00 00 00 02 00 00 00 29 00 00 00 05 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 02 00 00 00 1a 00 00 00 17 00 00 00 09 } //1
		$a_81_1 = {63 62 32 30 62 32 36 30 2d 62 66 66 37 2d 34 65 32 66 2d 62 66 34 39 2d 36 35 61 35 31 36 36 37 63 33 66 37 } //1 cb20b260-bff7-4e2f-bf49-65a51667c3f7
		$a_81_2 = {47 61 72 61 67 65 4d 61 6e 61 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 GarageManager.Properties.Resources.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}