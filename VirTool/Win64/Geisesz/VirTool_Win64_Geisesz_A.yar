
rule VirTool_Win64_Geisesz_A{
	meta:
		description = "VirTool:Win64/Geisesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 5c 24 40 48 8b 4c 24 48 48 c7 c7 ff ff ff ff 0f b7 74 24 3e 44 0f b7 44 24 3c 41 89 c1 48 8b 44 24 58 ?? ?? ?? ?? e8 [0-11] bb 12 00 00 00 31 c9 31 ff 48 83 c4 } //1
		$a_03_1 = {55 48 89 e5 48 81 ec b0 01 00 00 ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 89 84 24 88 00 00 00 44 0f 11 bc 24 10 01 00 00 44 0f 11 bc 24 20 01 00 00 31 c9 31 d2 31 db 31 f6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}