
rule Trojan_Win32_GuLoader_SIBU2_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 69 6e 67 } //1  Setup: Installing
		$a_03_1 = {bb 81 34 1a ?? ?? ?? ?? [0-3a] 43 [0-35] 43 [0-35] 43 [0-3a] 43 [0-2a] 81 fb ?? ?? ?? ?? [0-30] 0f 85 ?? ?? ?? ?? 90 08 52 01 81 36 ?? ?? ?? ?? [0-81] 36 ?? ?? ?? ?? [0-ff] d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}