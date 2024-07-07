
rule Trojan_Win64_Bumblebee_MOB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2d 18 27 00 00 48 01 83 48 03 00 00 48 8b 83 98 00 00 00 49 03 c2 48 01 81 58 02 00 00 48 8b 43 30 48 63 93 c0 03 00 00 48 8b 4b 08 8a 14 0a 42 32 14 00 48 8b 43 70 41 88 14 00 81 bb 50 03 00 00 62 27 00 00 75 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}