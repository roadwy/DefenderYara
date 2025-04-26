
rule VirTool_Win32_BilapLdz_B_MTB{
	meta:
		description = "VirTool:Win32/BilapLdz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 76 04 56 68 5c 21 40 00 e8 } //1
		$a_00_1 = {c7 85 e0 fd ff ff 00 00 00 00 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 68 90 01 04 ff } //1
		$a_00_2 = {88 44 35 ec 46 83 fe 10 72 e6 } //1
		$a_02_3 = {6a 00 8d 85 ?? ?? ?? ?? 50 57 56 53 ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}