
rule VirTool_Win32_Vcladru_A_dr{
	meta:
		description = "VirTool:Win32/Vcladru.A!dr,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 0a 6a 00 e8 } //1
		$a_03_1 = {6a 02 68 00 00 00 40 8d 85 ?? fe ff ff 8b d3 e8 ?? ?? ff ff 8b 8d } //1
		$a_03_2 = {50 56 6a 00 e8 ?? fe ff ff 50 e8 ?? fe ff ff 50 57 e8 ?? fe ff ff } //1
		$a_03_3 = {8b 55 f4 e8 ?? ?? ff ff 8b 85 ?? fe ff ff e8 ?? ?? ff ff 50 68 ?? ?? ?? ?? 6a 00 e8 ?? fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}