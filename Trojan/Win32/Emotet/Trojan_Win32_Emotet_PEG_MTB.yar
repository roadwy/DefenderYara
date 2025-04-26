
rule Trojan_Win32_Emotet_PEG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8a 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 94 14 ?? ?? ?? ?? 32 ca 85 c0 88 4c 24 90 09 0e 00 8a 84 14 ?? ?? ?? ?? 03 c1 b9 } //1
		$a_02_1 = {0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 54 14 ?? 32 54 24 } //1
		$a_81_2 = {73 66 52 31 72 49 54 4f 79 52 34 33 4e 65 69 75 46 32 35 6a 6d 77 35 50 49 4e 34 66 54 4d 51 4c 56 51 4c 64 41 6b 62 } //1 sfR1rITOyR43NeiuF25jmw5PIN4fTMQLVQLdAkb
		$a_81_3 = {5a 78 78 6d 39 67 45 42 62 59 69 48 66 51 43 36 31 73 34 48 79 59 53 64 6b 6b 54 6e 42 42 72 51 } //1 Zxxm9gEBbYiHfQC61s4HyYSdkkTnBBrQ
		$a_81_4 = {65 49 56 46 75 48 75 38 4d 30 78 7a 45 4c 39 39 54 63 46 34 65 6d 34 6a 53 72 72 4e 46 6a 36 79 66 35 69 66 34 59 76 6f 34 4b 69 37 70 52 37 35 61 70 6b 66 35 69 38 44 4c 62 73 49 56 4b 4a 47 56 53 73 48 31 38 78 46 6e 52 6d 32 6a } //1 eIVFuHu8M0xzEL99TcF4em4jSrrNFj6yf5if4Yvo4Ki7pR75apkf5i8DLbsIVKJGVSsH18xFnRm2j
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=1
 
}