
rule VirTool_Win64_Geinjesz_A{
	meta:
		description = "VirTool:Win64/Geinjesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 04 00 00 00 48 03 c2 ?? ?? ?? ?? 8b 04 8f ?? ?? ?? ?? 85 c0 ?? ?? 33 d2 85 c0 ?? ?? ?? 41 8b 48 2c 0f b6 47 20 03 ca ff c2 42 30 04 31 41 3b 12 } //1
		$a_03_1 = {0f b7 02 44 0f b7 c0 66 23 c3 66 3b c7 ?? ?? 41 8b 0a 41 81 e0 ff 0f 00 00 ?? ?? ?? ?? 4c 01 1c 01 48 83 c2 02 49 83 e9 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}