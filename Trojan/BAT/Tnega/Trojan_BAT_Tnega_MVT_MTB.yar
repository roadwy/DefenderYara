
rule Trojan_BAT_Tnega_MVT_MTB{
	meta:
		description = "Trojan:BAT/Tnega.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 28 44 00 00 06 6f 48 00 00 06 72 de 0d 00 70 28 28 00 00 0a 08 72 f4 0d 00 70 28 28 00 00 0a 6f 3c 00 00 0a } //1
		$a_00_1 = {43 3a 5c 77 6f 72 6b 73 70 61 63 65 5c 6d 75 64 66 69 78 5c 61 74 74 61 63 68 5c 73 63 72 65 65 6e 5f 62 6c 6f 63 6b 5c 67 65 6e 65 72 61 6c 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 67 65 6e 65 72 61 6c 2e 70 64 62 } //1 C:\workspace\mudfix\attach\screen_block\general\obj\Release\general.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}