
rule _PseudoThreat_c0001055{
	meta:
		description = "!PseudoThreat_c0001055,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 48 ff ff ff 40 89 85 48 ff ff ff 8b 85 58 ff ff ff 8b 8d 48 ff ff ff 3b 48 02 73 1c 8b 45 f0 03 85 48 ff ff ff 8b 8d 58 ff ff ff 03 8d 48 ff ff ff 8a 49 3a 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}