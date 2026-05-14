
rule Trojan_Win32_Farfli_SXF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f ef c8 66 0f f8 ca 0f 11 89 ?? ?? ?? ?? 83 c1 10 81 f9 00 dc 01 00 72 d8 } //20
		$a_03_1 = {44 6f 77 6e c7 85 ?? ?? ?? ?? 6c 6f 61 64 f3 0f 7e 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 73 5c 2a 2e } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}