
rule VirTool_Win32_PeStaple_gen_dr{
	meta:
		description = "VirTool:Win32/PeStaple.gen!dr,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 80 68 ?? ?? ?? ?? e8 ?? ?? 00 00 a3 ?? ?? ?? ?? 83 f8 ff 0f 84 ?? ?? 00 00 8b 15 ?? ?? ?? ?? 81 c2 05 01 00 00 f7 da 6a 02 6a 00 52 ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 6a 00 68 ?? ?? ?? ?? 68 00 01 00 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 6a 00 68 ?? ?? ?? ?? 6a 04 } //1
		$a_02_1 = {ba 00 00 00 00 bb 00 04 00 00 f7 f3 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 bb ?? ?? ?? ?? b9 00 04 00 00 f6 13 43 e2 fb 6a 00 } //1
		$a_02_2 = {eb 05 6f 70 65 6e 00 ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? 00 00 e9 ?? ?? ff ff ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 b8 00 00 00 00 c3 } //1
		$a_00_3 = {46 72 65 65 4a 6f 69 6e 65 72 20 62 79 20 47 6c 4f 46 46 00 } //1 牆敥潊湩牥戠⁹汇䙏F
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}