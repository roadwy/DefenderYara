
rule Trojan_Win32_Guloader_SIBU4_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU4!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {47 00 69 00 61 00 6e 00 74 00 44 00 6f 00 63 00 6b 00 } //1 GiantDock
		$a_03_1 = {cd 81 34 1a ?? ?? ?? ?? [0-30] 43 [0-35] 43 [0-40] 43 [0-25] 43 [0-35] 81 fb ?? ?? ?? ?? [0-10] eb 20 [0-25] 0f 85 ?? ?? ?? ?? [0-aa] 81 2e ?? ?? ?? ?? [0-40] 81 36 ?? ?? ?? ?? [0-b5] ff d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}