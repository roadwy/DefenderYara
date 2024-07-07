
rule Worm_Win32_Gamarue_AO{
	meta:
		description = "Worm:Win32/Gamarue.AO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 0c 6a ff c7 45 ec 07 80 00 00 ff 50 18 e8 90 01 04 8d 98 90 01 04 ff 73 10 8b 45 0c 8d 73 90 01 01 56 33 ff 57 89 5d d8 ff 50 10 90 00 } //1
		$a_01_1 = {80 3e eb 75 1b 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 83 7d 18 0a 75 c2 33 c0 eb 27 8b 45 08 57 8b 7d 10 53 56 57 ff 50 30 2b f7 8d 04 3b c6 00 e9 83 ee 05 89 70 01 8b 45 14 89 38 } //1
		$a_01_2 = {80 3e eb 75 13 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 eb b9 50 56 ff 75 f8 ff 55 dc 8b 45 f8 8b 4d fc c6 04 08 e9 8b 45 f8 8b 4d fc 2b f0 83 ee 05 89 74 08 01 } //1
		$a_01_3 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef } //5
		$a_01_4 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad } //5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=10
 
}