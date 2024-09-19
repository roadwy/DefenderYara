
rule _PseudoThreat_c0000af9{
	meta:
		description = "!PseudoThreat_c0000af9,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 4c 24 ?? 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 04 33 31 44 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}