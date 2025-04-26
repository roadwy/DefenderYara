
rule TrojanSpy_AndroidOS_Anubis_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Anubis.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 00 21 72 35 20 3c 00 52 62 4d 00 d8 02 02 01 d4 22 00 01 59 62 4d 00 52 62 4e 00 54 63 4c 00 52 64 4d 00 44 03 03 04 b0 32 d4 22 00 01 59 62 4e 00 52 62 4d 00 52 63 4e 00 54 64 4c 00 70 40 ?? ?? 26 43 54 62 4c 00 54 63 4c 00 52 64 4d 00 44 03 03 04 54 64 4c 00 52 65 4e 00 44 04 04 05 b0 43 d4 33 00 01 44 02 02 03 48 03 07 00 b7 32 8d 22 4f 02 01 00 d8 00 00 01 28 c4 11 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}