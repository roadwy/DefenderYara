
rule Trojan_Win32_Gozi_ES_MTB{
	meta:
		description = "Trojan:Win32/Gozi.ES!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 97 02 00 00 9b 8b 84 24 64 02 00 00 89 c1 83 e9 53 0f 94 c2 8b b4 24 6c 02 00 00 29 c6 0f 94 c6 8b bc 24 90 02 00 00 89 fb 81 c3 d5 9f 04 c4 89 44 24 6c 29 d8 0f 94 c3 81 f7 2d 60 fb 3b 89 44 24 68 8b 44 24 6c 83 e8 03 0f 94 c7 89 74 24 64 66 8b b4 24 ba 00 00 00 66 81 c6 6b 66 39 bc 24 64 02 00 00 89 44 24 60 0f 94 c0 66 89 b4 24 a8 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}