
rule TrojanClicker_BAT_Jalapeno_AJL_MTB{
	meta:
		description = "TrojanClicker:BAT/Jalapeno.AJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 17 13 06 2b 49 11 06 18 5d 2d 1d 11 04 08 72 93 00 00 70 02 11 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 26 2b 20 11 04 08 6f ?? 00 00 0a 72 93 00 00 70 02 11 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 26 11 06 17 58 13 06 11 06 06 31 b2 } //3
		$a_03_1 = {16 0a 02 7b 0b 00 00 04 0d 12 03 28 ?? 00 00 0a 0b 16 0c 2b 12 07 08 6f ?? 00 00 0a 13 04 06 11 04 58 0a 08 17 58 0c 08 07 6f ?? 00 00 0a 32 e5 } //1
		$a_01_2 = {54 65 6d 70 62 75 69 6c 64 5c 41 64 69 7a 75 6b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 41 64 69 7a 75 6b 2e 70 64 62 } //2 Tempbuild\Adizuk\obj\Release\Adizuk.pdb
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=6
 
}