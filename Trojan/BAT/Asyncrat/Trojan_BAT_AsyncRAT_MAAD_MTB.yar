
rule Trojan_BAT_AsyncRAT_MAAD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MAAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 13 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e7 } //01 00 
		$a_01_1 = {31 63 32 38 64 61 66 34 2d 62 61 30 33 2d 34 65 66 33 2d 39 37 61 61 2d 64 32 31 37 63 39 37 30 66 31 30 61 } //00 00  1c28daf4-ba03-4ef3-97aa-d217c970f10a
	condition:
		any of ($a_*)
 
}