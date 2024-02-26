
rule Trojan_Win32_Zbot_ASC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {bf e8 48 d7 a8 79 c9 6f 32 43 fe 47 39 43 d8 50 23 63 d5 5a 32 56 d9 28 bf 11 4b d7 a8 79 } //01 00 
		$a_01_1 = {33 f9 c4 00 cc 67 81 b1 ce 74 33 96 2b ee 43 b1 25 84 b7 71 27 5a 29 34 29 e7 d9 bb ff bd 58 31 } //00 00 
	condition:
		any of ($a_*)
 
}