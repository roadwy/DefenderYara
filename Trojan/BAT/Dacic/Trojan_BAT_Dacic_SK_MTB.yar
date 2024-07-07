
rule Trojan_BAT_Dacic_SK_MTB{
	meta:
		description = "Trojan:BAT/Dacic.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 7b 0c 00 00 04 7b 27 00 00 04 07 17 58 0e 04 07 9a 05 6f 90 01 03 06 07 9a 28 90 01 03 06 6f 90 01 03 06 07 17 58 0b 07 6e 0e 04 8e 69 6a 32 cf 90 00 } //2
		$a_01_1 = {5c 63 68 61 72 6d 68 6f 73 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 63 68 61 72 6d 68 6f 73 74 2e 70 64 62 } //2 \charmhost\obj\Release\charmhost.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}