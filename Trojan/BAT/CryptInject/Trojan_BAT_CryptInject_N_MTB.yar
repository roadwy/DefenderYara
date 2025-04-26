
rule Trojan_BAT_CryptInject_N_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {57 3f b6 1f 09 0f 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 00 01 00 00 20 } //1
		$a_81_1 = {46 6c 75 78 75 73 20 56 37 2e 65 78 65 } //1 Fluxus V7.exe
		$a_01_2 = {46 6c 75 78 75 73 5f 49 44 45 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Fluxus_IDE.Properties.Resources.resources
		$a_81_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_4 = {5c 52 6f 62 6c 6f 78 50 6c 61 79 65 72 42 65 74 61 2e 65 78 65 } //1 \RobloxPlayerBeta.exe
		$a_81_5 = {2f 43 20 49 6e 6a 65 63 74 2e 62 61 74 } //1 /C Inject.bat
		$a_81_6 = {5c 62 69 6e 5c 44 69 73 63 6f 72 64 2e 46 6c 75 78 75 73 } //1 \bin\Discord.Fluxus
		$a_81_7 = {44 41 43 49 6e 6a 65 63 74 2e 65 78 65 } //1 DACInject.exe
		$a_81_8 = {72 62 78 73 63 72 69 70 74 73 2e 78 79 7a } //1 rbxscripts.xyz
		$a_81_9 = {2f 46 6c 75 78 75 73 54 65 61 6d 41 50 49 2e 64 6c 6c } //1 /FluxusTeamAPI.dll
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}