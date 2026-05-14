
rule VirTool_Win64_Ruclebesz_A{
	meta:
		description = "VirTool:Win64/Ruclebesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 14 08 44 0f b6 44 08 02 41 c1 e0 10 41 09 d0 41 81 f8 c3 cc cc 00 ?? ?? 0f b7 54 08 01 44 0f b6 44 08 03 41 c1 e0 10 41 09 d0 41 81 f8 c3 cc cc 00 } //1
		$a_03_1 = {48 ff ce 48 ff c9 48 83 f9 01 ?? ?? 80 3e 74 ?? ?? 48 0f be 46 01 ?? ?? ?? ?? 48 81 fa ff 0f 00 00 ?? ?? 80 7c 06 02 b8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}