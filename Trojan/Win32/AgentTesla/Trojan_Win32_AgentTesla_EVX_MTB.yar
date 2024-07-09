
rule Trojan_Win32_AgentTesla_EVX_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.EVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //1
		$a_01_1 = {45 78 63 65 70 2e 74 63 74 } //1 Excep.tct
		$a_01_2 = {74 69 6f 6e 43 61 74 63 68 65 72 } //1 tionCatcher
		$a_01_3 = {4d 59 39 34 37 } //1 MY947
		$a_01_4 = {39 34 37 5c 52 65 6c 65 61 73 65 5c 39 34 37 2e 70 64 62 } //1 947\Release\947.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}