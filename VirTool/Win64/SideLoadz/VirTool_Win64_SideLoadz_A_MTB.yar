
rule VirTool_Win64_SideLoadz_A_MTB{
	meta:
		description = "VirTool:Win64/SideLoadz.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 c0 48 8d 54 24 50 48 03 d0 0f b6 02 44 88 0a 88 04 39 8b c8 0f b6 02 48 03 c8 0f b6 c1 0f b6 4c 04 50 41 32 0c 1b 88 0b 48 ff c3 49 83 ea 01 75 94 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}