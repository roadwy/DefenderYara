
rule Worm_Win32_Gamarue_AQ_{
	meta:
		description = "Worm:Win32/Gamarue.AQ!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 3e eb 75 1b 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 83 7d 18 0a 75 c2 33 c0 eb 27 8b 45 08 57 8b 7d 10 53 56 57 ff 50 30 2b f7 8d 04 3b c6 00 e9 83 ee 05 89 70 01 8b 45 14 89 38 } //1
		$a_01_1 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef } //5
		$a_01_2 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=11
 
}