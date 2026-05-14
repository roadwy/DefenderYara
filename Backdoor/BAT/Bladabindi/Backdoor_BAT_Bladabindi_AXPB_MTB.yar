
rule Backdoor_BAT_Bladabindi_AXPB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AXPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 0b 2b 42 00 02 07 17 59 6f ?? 00 00 0a 28 ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 28 ?? 00 00 0a 59 2b 2d 06 08 d1 13 04 12 04 28 ?? 00 00 0a 28 ?? 00 00 0a 2b 07 00 07 17 58 0b 2b 03 0a 2b f6 07 02 6f ?? 00 00 0a fe 02 16 fe 01 13 05 2b 03 0c 2b d0 11 05 2d 02 2b 05 2b a3 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}