
rule VirTool_BAT_CryptInject_AP_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.AP!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 43 6c 69 65 6e 74 50 6c 75 67 69 6e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 43 6c 69 65 6e 74 50 6c 75 67 69 6e 2e 70 64 62 } //1 \ClientPlugin\obj\Release\ClientPlugin.pdb
		$a_01_1 = {43 6c 69 65 6e 74 50 6c 75 67 69 6e 2e 64 6c 6c } //1 ClientPlugin.dll
		$a_01_2 = {24 31 64 34 63 63 30 64 37 2d 34 62 34 62 2d 34 66 33 30 2d 61 34 65 31 2d 37 31 62 65 32 65 36 64 30 32 39 39 } //1 $1d4cc0d7-4b4b-4f30-a4e1-71be2e6d0299
		$a_01_3 = {49 43 6c 69 65 6e 74 4d 61 69 6e } //1 IClientMain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}