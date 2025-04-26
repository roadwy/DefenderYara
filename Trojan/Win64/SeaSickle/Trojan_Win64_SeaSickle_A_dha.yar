
rule Trojan_Win64_SeaSickle_A_dha{
	meta:
		description = "Trojan:Win64/SeaSickle.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {8d 49 02 f7 e9 41 8b c9 c1 fa 03 8b c2 c1 e8 1f 03 d0 8d 04 92 c1 e0 02 2b c8 8d 41 02 42 0f b6 4c 13 01 48 98 42 2a 0c 18 b8 90 01 04 41 88 4a 01 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}