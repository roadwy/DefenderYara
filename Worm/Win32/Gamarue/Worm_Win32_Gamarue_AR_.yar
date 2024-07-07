
rule Worm_Win32_Gamarue_AR_{
	meta:
		description = "Worm:Win32/Gamarue.AR!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 3e eb 75 13 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 eb b9 50 56 ff 75 f8 ff 55 dc 8b 45 f8 8b 4d fc c6 04 08 e9 8b 45 f8 8b 4d fc 2b f0 83 ee 05 89 74 08 01 } //1
		$a_01_1 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef } //5
		$a_01_2 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=11
 
}