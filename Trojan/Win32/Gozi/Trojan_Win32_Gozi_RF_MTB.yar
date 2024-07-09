
rule Trojan_Win32_Gozi_RF_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d d0 89 4d f0 8b 55 cc 89 55 f8 8b 45 cc 89 45 e0 8b 4d e0 8b 11 33 55 f0 8b 45 e0 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 18 00 00 00 89 45 fc 8b 45 fc 05 c0 00 00 00 05 e0 00 00 00 01 c8 89 45 f8 8b 45 f8 89 45 fc 8b 4d fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 fe ff ff 0f b6 ?? 8b 85 04 fe ff ff 99 be ?? 00 00 00 f7 fe 8b 85 64 fe ff ff 0f b6 14 10 33 ca 8b 85 ?? fe ff ff 03 85 ?? fe ff ff 88 08 eb aa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 54 24 79 68 72 74 67 66 64 72 34 68 65 72 79 } //1 CT$yhrtgfdr4hery
		$a_01_1 = {76 00 65 00 72 00 79 00 44 00 61 00 54 00 73 00 69 00 67 00 6e 00 73 00 79 00 } //1 veryDaTsignsy
		$a_01_2 = {77 00 6f 00 6e 00 2e 00 74 00 6b 00 57 00 69 00 74 00 68 00 6f 00 75 00 74 00 54 00 77 00 6f 00 } //1 won.tkWithoutTwo
		$a_01_3 = {58 00 6d 00 61 00 6e 00 79 00 69 00 65 00 6c 00 64 00 69 00 6e 00 67 00 49 00 7a 00 74 00 6f 00 66 00 61 00 63 00 65 00 67 00 } //1 XmanyieldingIztofaceg
		$a_01_4 = {67 00 69 00 76 00 65 00 6e 00 69 00 6e 00 63 00 6f 00 66 00 36 00 41 00 70 00 } //1 givenincof6Ap
		$a_01_5 = {41 00 6c 00 6c 00 37 00 75 00 6e 00 74 00 6f 00 67 00 48 00 6b 00 6c 00 } //1 All7untogHkl
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}