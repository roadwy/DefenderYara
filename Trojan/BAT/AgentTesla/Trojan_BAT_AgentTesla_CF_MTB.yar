
rule Trojan_BAT_AgentTesla_CF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 69 6c 65 20 48 65 6b 69 6d 69 6e 64 65 6e 20 62 69 72 69 6e 69 6e 20 4e 42 59 53 } //1 Aile Hekiminden birinin NBYS
		$a_01_1 = {74 65 72 63 69 68 20 65 74 6d 65 73 69 6e 69 6e 20 6f 6e 75 72 75 6e 75 20 79 61 } //1 tercih etmesinin onurunu ya
		$a_01_2 = {35 54 65 6c 69 66 20 48 61 6b 6b } //1 5Telif Hakk
		$a_01_3 = {24 61 63 30 34 35 65 32 35 2d 35 64 39 65 2d 34 32 62 38 2d 61 31 63 65 2d 34 63 33 61 39 35 39 36 30 65 61 65 } //1 $ac045e25-5d9e-42b8-a1ce-4c3a95960eae
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_CF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 07 00 00 "
		
	strings :
		$a_00_0 = {0a 28 41 00 00 06 26 14 0a 2b 00 06 2a } //10
		$a_02_1 = {0a 0a 02 06 6f ?? ?? ?? 0a 1f 09 9a } //10
		$a_02_2 = {00 07 08 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 13 04 11 04 16 fe 02 13 05 11 05 2c 0c } //10
		$a_81_3 = {41 5a 58 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 } //1 AZXCCCCCCCCCCCCCCCCCCC
		$a_81_4 = {69 6d 69 6d 69 6d 69 6d 69 6d } //1 imimimimim
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {74 66 32 6d 6f 64 75 74 69 6c 2e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 tf2modutil.Main.resources
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=34
 
}