
rule VirTool_Win32_PeCloak_MTB{
	meta:
		description = "VirTool:Win32/PeCloak!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 f6 31 ff 90 02 30 3d 90 01 04 75 90 02 30 3d 90 01 04 75 90 02 30 3d 90 01 04 75 90 02 30 b8 90 02 10 80 30 90 02 30 80 28 90 02 30 80 00 90 02 30 40 3d 90 01 04 7e 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}