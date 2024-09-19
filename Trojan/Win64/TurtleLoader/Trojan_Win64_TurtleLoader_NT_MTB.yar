
rule Trojan_Win64_TurtleLoader_NT_MTB{
	meta:
		description = "Trojan:Win64/TurtleLoader.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 30 8b 44 24 3c c1 f8 02 89 44 24 3c 83 7c 24 3c 00 0f 8e ?? ?? ?? ?? 48 8b 44 24 40 0f b6 40 01 c1 e0 08 48 8b 4c 24 40 0f b6 09 01 c8 03 44 24 38 } //3
		$a_03_1 = {48 89 4c 24 40 48 8b 4c 24 40 e8 ?? ?? ?? ?? 89 44 24 3c 8b 44 24 3c } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}