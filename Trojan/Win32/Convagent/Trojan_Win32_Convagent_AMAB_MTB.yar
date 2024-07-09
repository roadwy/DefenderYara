
rule Trojan_Win32_Convagent_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 df 33 d8 2b f3 8b d6 c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 } //5
		$a_03_1 = {33 cf 31 4c 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}