
rule _PseudoThreat_c0000b8f{
	meta:
		description = "!PseudoThreat_c0000b8f,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec ?? 53 (33 c9 56 57 89 4d|56 57 c7 45) [0-20] 99 f7 7d 0c 8b ?? ?? 90 03 01 01 89 8b ?? ?? 90 03 01 01 89 8b [0-0a] 88 45 ff 60 33 c0 8a 45 ff 33 c9 8b 4d f4 d2 c8 88 45 ff 61 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}