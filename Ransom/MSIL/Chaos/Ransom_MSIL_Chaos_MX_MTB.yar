
rule Ransom_MSIL_Chaos_MX_MTB{
	meta:
		description = "Ransom:MSIL/Chaos.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 28 0c 00 00 06 0b 1f 0c 8d ?? 00 00 01 0c 73 1b 00 00 0a 13 05 11 05 08 6f 1c 00 00 0a de 0c } //2
		$a_00_1 = {57 69 6e 4c 6f 63 6b 65 72 43 6f 64 65 72 } //1 WinLockerCoder
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}