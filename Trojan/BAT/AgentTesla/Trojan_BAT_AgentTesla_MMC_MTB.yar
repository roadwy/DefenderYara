
rule Trojan_BAT_AgentTesla_MMC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 3a 01 00 70 72 54 01 00 70 72 d0 01 00 70 72 e0 01 00 70 28 1c 00 00 0a } //1
		$a_00_1 = {57 69 6e 46 6f 72 6d 47 72 65 67 6f 72 43 61 74 63 68 2e 65 78 65 } //1 WinFormGregorCatch.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}