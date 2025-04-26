
rule Trojan_Win32_GuLoader_SIBU_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 6f 76 65 6e 74 72 69 65 73 20 53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 69 6e 67 } //1 Coventries Setup: Installing
		$a_03_1 = {aa 81 34 1a ?? ?? ?? ?? [0-40] 43 [0-3a] 43 [0-40] 43 [0-30] 43 [0-2a] 81 fb ?? ?? ?? ?? [0-30] 0f 85 ?? ?? ?? ?? [0-3a] 90 08 bc 01 ff d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}