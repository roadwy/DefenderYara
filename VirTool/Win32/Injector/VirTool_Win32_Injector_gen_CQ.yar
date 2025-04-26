
rule VirTool_Win32_Injector_gen_CQ{
	meta:
		description = "VirTool:Win32/Injector.gen!CQ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 64 61 74 65 20 79 6f 75 20 70 69 63 6b 65 64 20 69 73 3a 00 } //10
		$a_03_1 = {64 a1 30 00 00 00 eb 90 14 8b 40 0c eb 90 14 8b 40 14 eb } //1
		$a_03_2 = {8d 45 fc eb 90 14 0f 81 ?? ?? ff ff e9 ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}