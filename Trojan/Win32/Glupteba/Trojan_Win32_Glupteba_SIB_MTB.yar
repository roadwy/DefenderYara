
rule Trojan_Win32_Glupteba_SIB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 d6 8b 55 90 01 01 52 83 e2 00 0b 55 0c 83 e7 00 31 d7 5a 50 51 8b 4e 90 01 01 89 4c e4 04 59 57 6a 90 02 04 89 34 e4 31 f6 0b b3 90 01 04 89 f1 5e 56 89 ce 81 c6 90 01 04 89 f1 5e 51 50 8b 06 56 8f 45 90 01 01 01 45 90 1b 05 ff 75 90 1b 05 5e 58 a4 49 75 90 01 01 59 5f 52 2b 14 e4 31 fa 83 e6 00 09 d6 5a 53 0f b6 06 46 85 c0 74 4e 51 55 c7 04 e4 90 01 04 59 bb 00 00 00 00 89 45 90 01 01 83 e0 00 09 f0 83 e2 00 09 c2 8b 45 90 1b 0a 21 5d 90 01 01 57 8b 7d 90 1b 0c 81 c7 90 01 04 89 7d 90 1b 0c 5f d3 c0 8a fc 8a e6 d3 cb ff 4d 90 1b 0c 75 90 01 01 59 89 55 90 01 01 2b 55 90 1b 12 09 da 83 e0 00 09 d0 8b 55 90 1b 12 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}