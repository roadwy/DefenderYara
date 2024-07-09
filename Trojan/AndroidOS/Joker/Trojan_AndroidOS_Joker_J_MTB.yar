
rule Trojan_AndroidOS_Joker_J_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 0e 12 0f 71 20 ?? ?? fe 00 0c 04 22 0a ?? ?? 6e 10 ?? ?? 0c 00 0c 0e 70 20 ?? ?? ea 00 22 07 ?? ?? 70 20 ?? ?? 47 00 12 08 6e 10 ?? ?? 07 00 0a 08 12 fe 32 e8 ?? ?? 14 0e 40 e2 01 00 b7 8e 6e 20 ?? ?? ea 00 } //1
		$a_00_1 = {63 6f 6d 2f 6b 65 79 79 74 2f 62 6f 61 72 64 2f 6c 6f 66 75 74 72 6e 68 73 75 6f 73 } //1 com/keyyt/board/lofutrnhsuos
		$a_03_2 = {70 73 3a 2f 2f [0-14] 2e 73 33 2e 75 73 2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}