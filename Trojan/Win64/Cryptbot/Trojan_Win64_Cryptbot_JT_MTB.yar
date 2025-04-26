
rule Trojan_Win64_Cryptbot_JT_MTB{
	meta:
		description = "Trojan:Win64/Cryptbot.JT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 ca 48 8b c7 41 ff c2 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 49 0f af cf 8a 44 0d a7 43 32 04 19 41 88 03 49 ff c3 41 81 fa 00 ba 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}