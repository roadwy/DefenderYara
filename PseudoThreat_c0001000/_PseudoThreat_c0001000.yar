
rule _PseudoThreat_c0001000{
	meta:
		description = "!PseudoThreat_c0001000,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 e8 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}