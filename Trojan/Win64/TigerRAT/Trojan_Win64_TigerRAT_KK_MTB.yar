
rule Trojan_Win64_TigerRAT_KK_MTB{
	meta:
		description = "Trojan:Win64/TigerRAT.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 c8 41 88 4c 10 fe 0f b6 4a fe 0f b6 42 ff c0 e1 07 d0 e8 32 c8 41 88 4c 10 ff 0f b6 72 ff 40 c0 e6 07 49 83 e9 01 75 } //20
		$a_01_1 = {32 d8 8b c1 c1 f8 02 24 01 32 d8 8b c1 c1 f8 03 24 01 32 d8 8b c1 c1 f8 04 24 01 32 d8 8b c1 c1 f8 05 24 01 32 d8 8b c1 c1 f8 06 24 01 c1 f9 07 32 d8 80 e1 01 32 d9 48 83 ef 01 75 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}