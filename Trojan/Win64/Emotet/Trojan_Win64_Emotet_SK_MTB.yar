
rule Trojan_Win64_Emotet_SK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 cf f3 3c cf 41 f7 e8 c1 fa 02 8b c2 c1 e8 1f 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 15 48 03 c8 48 8d 05 45 dd 08 00 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72 c3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}