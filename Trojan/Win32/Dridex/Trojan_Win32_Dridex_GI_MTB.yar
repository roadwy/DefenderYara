
rule Trojan_Win32_Dridex_GI_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 66 69 6c 65 61 70 69 2e 67 79 78 } //1 cfileapi.gyx
		$a_01_1 = {57 69 6e 48 74 74 70 4f 70 65 6e } //1 WinHttpOpen
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {56 4d 50 72 6f 74 65 63 74 20 62 65 67 69 6e } //1 VMProtect begin
		$a_01_4 = {61 6f 2e 74 6f 70 2f 30 30 31 2f 70 75 70 70 65 } //1 ao.top/001/puppe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}