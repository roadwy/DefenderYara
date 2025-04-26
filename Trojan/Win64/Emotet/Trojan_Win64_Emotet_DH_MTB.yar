
rule Trojan_Win64_Emotet_DH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b ca 49 83 c1 01 49 83 c2 01 41 f7 e0 41 8b c0 41 83 c0 01 2b c2 d1 e8 03 c2 c1 e8 04 48 6b c0 13 48 2b c8 0f b6 04 19 41 32 44 29 ff 45 3b c4 41 88 41 ff 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}