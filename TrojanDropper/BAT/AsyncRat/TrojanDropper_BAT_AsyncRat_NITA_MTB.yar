
rule TrojanDropper_BAT_AsyncRat_NITA_MTB{
	meta:
		description = "TrojanDropper:BAT/AsyncRat.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 10 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a } //2
		$a_03_1 = {7e 01 00 00 04 28 ?? 00 00 06 13 0d 28 ?? 00 00 0a 13 0e 11 0e 72 87 00 00 70 28 ?? 00 00 0a 13 15 12 15 fe 16 16 00 00 01 6f 19 00 00 0a 11 0b 16 6f 1a 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0f 11 0f 11 0d 28 ?? 00 00 0a 11 0f 28 ?? 00 00 0a 26 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}