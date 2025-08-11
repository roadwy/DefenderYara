
rule TrojanDropper_Win32_Systex_AST_MTB{
	meta:
		description = "TrojanDropper:Win32/Systex.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 3f 00 0f 00 53 53 ff 15 ?? ?? ?? ?? 6a 02 8b f0 68 70 bb 40 00 56 ff 15 ?? ?? ?? ?? 53 53 53 53 53 53 53 6a ff 6a 03 8b f8 6a ff 57 } //3
		$a_03_1 = {83 c4 04 e8 ?? ?? ?? ?? 99 b9 1a 00 00 00 f7 f9 6a 14 8b da ff d7 80 c3 61 6a 1e 88 9c 34 c8 00 00 00 ff d7 46 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}