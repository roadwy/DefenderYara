
rule Trojan_AndroidOS_TrojanDropper_AB{
	meta:
		description = "Trojan:AndroidOS/TrojanDropper.AB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {dd 4a dd 4b d0 f8 84 60 7a 44 7b 44 58 46 b0 47 02 46 da 48 29 46 78 44 d0 f8 00 80 58 46 c0 47 81 46 db f8 00 00 d6 49 82 69 79 44 58 46 90 47 05 46 db f8 00 00 d3 4a 29 46 d3 4b d0 f8 84 60 7a 44 7b 44 58 46 b0 47 06 46 db f8 00 00 cf 4a 29 46 d0 f8 84 40 7a 44 ce 4b 58 46 7b 44 a0 47 06 90 } //2
		$a_02_1 = {6c 69 62 63 2e 73 6f 00 6c 69 62 ?? ?? 2e 73 6f 00 5f 5f 63 78 61 5f 66 69 6e 61 6c 69 7a 65 00 [0-31] 4a 61 76 61 5f 6a 5f 6b 63 5f 67 61 7a 00 4a 61 76 61 5f 6a 5f 6f 69 5f 62 62 66 00 4a 61 76 61 5f 6a 5f 6f 69 5f 64 76 67 00 4a 61 76 61 5f 6a 5f 6f 69 5f 65 7a 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}