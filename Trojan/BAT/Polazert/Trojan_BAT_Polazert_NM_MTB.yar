
rule Trojan_BAT_Polazert_NM_MTB{
	meta:
		description = "Trojan:BAT/Polazert.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 1d a2 c9 09 0a 00 00 00 fa 25 33 00 16 00 00 57 00 00 00 3b 00 00 00 04 00 00 00 15 00 00 00 21 00 00 00 1d 00 00 00 6f 00 00 00 03 00 00 00 1a 00 00 00 12 00 00 00 01 00 00 00 03 00 00 00 03 00 00 00 06 } //1
		$a_01_1 = {53 62 79 67 6d 57 6a 66 69 77 65 68 79 62 70 6d 6c } //1 SbygmWjfiwehybpml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}