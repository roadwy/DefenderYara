
rule VirTool_Win32_Cryptdru_gen_dr{
	meta:
		description = "VirTool:Win32/Cryptdru.gen!dr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 24 6a 01 6a 01 ff 15 ?? ?? ?? ?? 83 e8 63 0f 80 ?? 05 00 00 50 8b 55 dc 52 6a 64 ff 15 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? c7 85 ?? ff ff ff ?? ?? ?? ?? c7 85 ?? ff ff ff 08 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}