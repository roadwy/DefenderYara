
rule Trojan_AndroidOS_Joker_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 00 1a 03 00 00 1a 02 00 00 01 01 13 04 0f 00 34 41 24 00 22 01 ?? ?? 6e 10 ?? ?? 08 00 0a 04 db 04 04 02 70 20 ?? ?? 41 00 6e 10 ?? ?? 08 00 0a 04 3c 04 ?? ?? 6e 10 ?? ?? 01 00 0c 01 21 13 6e 10 ?? ?? 02 00 0a 04 34 30 54 00 22 00 ?? ?? 70 20 ?? ?? 10 00 11 00 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 20 ?? ?? 34 00 } //2
		$a_03_1 = {0c 03 71 10 cb 2e 01 00 0c 04 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 22 04 0b 08 70 10 ?? ?? 04 00 6e 20 ?? ?? 24 00 0c 02 71 00 ?? ?? 00 00 0b 04 13 06 0a 00 83 66 cd 64 8a 44 b7 14 6e 20 ?? ?? 42 00 0c 02 6e 10 ?? ?? 02 00 0c 02 d8 01 01 01 28 a8 12 e4 6e 20 ?? ?? 48 00 0a 04 6e 20 ?? ?? 43 00 0a 04 e0 04 04 04 12 f5 6e 20 ?? ?? 58 00 0a 05 6e 20 ?? ?? 53 00 0a 05 b6 54 6e 20 ?? ?? 41 00 28 9e 48 05 01 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}