
rule Trojan_Win64_Injector_SXF_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 83 c2 70 45 33 ed 4c 89 6c 24 20 41 b9 08 00 00 00 4c 8d 85 b8 00 00 00 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 c1 eb 20 48 89 9d } //20
		$a_01_1 = {49 6e 6a 65 63 74 65 64 } //5 Injected
		$a_01_2 = {52 6f 62 6c 6f 78 50 6c 61 79 65 72 42 65 74 61 2e 65 78 65 } //1 RobloxPlayerBeta.exe
		$a_01_3 = {57 61 69 74 69 6e 67 20 66 6f 72 20 68 6f 6f 6b } //1 Waiting for hook
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=27
 
}