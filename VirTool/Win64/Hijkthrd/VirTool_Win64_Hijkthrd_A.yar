
rule VirTool_Win64_Hijkthrd_A{
	meta:
		description = "VirTool:Win64/Hijkthrd.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 e8 1f 00 00 00 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f 5e 5d 5b 5a 59 58 66 9d ff 25 bb ff ff ff } //1
		$a_01_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}