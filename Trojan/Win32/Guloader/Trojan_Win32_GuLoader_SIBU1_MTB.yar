
rule Trojan_Win32_GuLoader_SIBU1_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 4f 4c 44 49 45 52 49 4e 47 20 53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 69 6e 67 } //1 SOLDIERING Setup: Installing
		$a_03_1 = {f9 81 34 1a ?? ?? ?? ?? [0-35] 43 [0-30] 43 [0-3a] 43 [0-30] 43 [0-3a] 81 fb ?? ?? ?? ?? [0-40] 0f 85 ?? ?? ?? ?? 90 08 3a 01 81 36 ?? ?? ?? ?? [0-40] 81 2e ?? ?? ?? ?? [0-3a] ff d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}