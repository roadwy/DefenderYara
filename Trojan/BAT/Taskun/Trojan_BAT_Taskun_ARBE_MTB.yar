
rule Trojan_BAT_Taskun_ARBE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 16 13 08 2b 4c 00 16 13 09 2b 34 00 09 11 06 11 08 58 17 58 17 59 11 07 11 09 58 17 58 17 59 6f 90 01 03 0a 13 0a 12 0a 28 90 01 03 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d c1 11 08 17 58 13 08 00 11 08 17 fe 04 13 0d 11 0d 2d a9 00 11 07 17 58 13 07 11 07 17 fe 04 13 0e 11 0e 2d 91 90 00 } //2
		$a_80_1 = {54 48 44 41 5f 47 72 6f 75 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //THDA_Group.Properties.Resources  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}