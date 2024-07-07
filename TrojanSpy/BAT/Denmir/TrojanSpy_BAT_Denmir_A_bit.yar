
rule TrojanSpy_BAT_Denmir_A_bit{
	meta:
		description = "TrojanSpy:BAT/Denmir.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6c 48 65 6c 70 65 72 } //1 StealHelper
		$a_00_1 = {44 00 65 00 6e 00 64 00 69 00 6d 00 69 00 72 00 72 00 6f 00 72 00 20 00 42 00 6f 00 74 00 6e 00 65 00 74 00 } //1 Dendimirror Botnet
		$a_00_2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 41 00 7a 00 75 00 72 00 65 00 53 00 44 00 4b 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 schtasks /create /tn AzureSDKService
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}