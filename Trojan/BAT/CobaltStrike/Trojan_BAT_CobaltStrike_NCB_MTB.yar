
rule Trojan_BAT_CobaltStrike_NCB_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 80 00 00 0a 20 90 01 03 00 28 90 01 03 06 20 90 01 03 00 14 14 18 8d 90 01 03 01 25 16 11 02 17 8d 90 01 03 01 25 16 11 04 8c 90 01 03 01 a2 14 28 90 01 03 0a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a 28 90 01 03 0a 90 00 } //5
		$a_01_1 = {31 79 6f 58 71 45 37 } //1 1yoXqE7
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}