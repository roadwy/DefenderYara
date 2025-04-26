
rule _PseudoThreat_c0000ed8{
	meta:
		description = "!PseudoThreat_c0000ed8,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 56 57 60 32 db 74 03 83 c4 50 61 60 e8 00 00 00 00 d1 c0 80 04 24 07 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}