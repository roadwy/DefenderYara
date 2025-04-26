
rule VirTool_Win64_Poxloadz_A_MTB{
	meta:
		description = "VirTool:Win64/Poxloadz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {48 8b 55 e0 48 8d ?? ?? 4c 8b 55 f8 41 b9 00 00 00 00 49 89 d0 48 8b ?? ?? ?? ?? ?? 48 89 c1 41 } //1
		$a_02_1 = {ba 00 10 00 00 48 c7 c1 ff ff ff ff 48 8b ?? ?? ?? ?? ?? ff } //1
		$a_02_2 = {48 89 c1 48 8d ?? ?? ?? ?? ?? 48 89 c2 48 8b ?? ?? ?? ?? ?? ff ?? 48 89 45 f8 } //1
		$a_02_3 = {48 89 d1 48 31 d2 e8 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}