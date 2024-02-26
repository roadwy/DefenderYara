
rule Trojan_Win32_Ekstak_ES_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 c2 53 6a 00 e4 b7 66 00 00 be 0a 00 d4 bd 14 99 8d 71 66 00 00 d4 00 00 ed 46 c5 3b } //01 00 
		$a_01_1 = {2a 01 00 00 00 e5 fe 69 00 07 63 66 00 00 be 0a 00 d4 bd 14 99 a2 1c 66 00 00 d4 00 00 8d b6 cc 53 } //01 00 
		$a_01_2 = {2a 01 00 00 00 2e 0e 6a 00 50 72 66 00 00 be 0a 00 d4 bd 14 99 eb 2b 66 00 00 d4 00 00 e8 74 c7 2d } //01 00 
		$a_01_3 = {2a 01 00 00 00 a8 27 6a 00 ca 8b 66 00 00 be 0a 00 d4 bd 14 99 60 45 66 00 00 d4 00 00 00 77 0a 7c } //01 00 
		$a_01_4 = {2a 01 00 00 00 b3 2b 6a 00 d5 8f 66 00 00 be 0a 00 d4 bd 14 99 67 49 66 00 00 d4 00 00 95 ca c3 31 } //01 00 
		$a_01_5 = {2a 01 00 00 00 30 78 6a 00 52 dc 66 00 00 be 0a 00 d4 bd 14 99 05 96 66 00 00 d4 00 00 c8 53 d5 ee } //00 00 
	condition:
		any of ($a_*)
 
}