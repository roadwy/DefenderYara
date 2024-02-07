
rule Trojan_Win32_Fareit_SS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 75 fc 03 f7 8a 03 88 45 fb 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fb 32 45 fa 88 06 8a 06 32 45 f9 88 06 eb 05 8a 45 fb 88 06 47 43 49 75 ca } //01 00 
		$a_02_1 = {75 11 8a 45 90 01 01 32 45 90 01 01 88 06 8a 06 32 45 90 01 01 88 06 eb 05 8a 45 90 01 01 88 06 47 43 49 75 ca 90 00 } //02 00 
		$a_00_2 = {8b 75 fc 03 f7 8a 03 88 45 fa 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fa 32 45 fb 88 06 8a 06 32 45 f9 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca } //00 00 
		$a_00_3 = {78 } //c3 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_SS_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 5d f8 03 de 8a 01 88 45 f7 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f7 32 45 f5 88 03 8a 03 32 45 f6 88 03 eb 05 8a 45 f7 88 03 46 41 4f 75 ca } //02 00 
		$a_00_1 = {8b 5d f8 03 de 8a 01 88 45 f6 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f6 32 45 f5 88 03 8a 03 32 45 f7 88 03 eb 05 8a 45 f6 88 03 46 41 4f 75 ca } //01 00 
		$a_03_2 = {8b 5d f8 03 de 8a 01 88 45 90 02 04 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 90 02 04 32 45 f5 88 03 8a 03 32 45 90 02 04 88 03 eb 05 8a 45 90 02 04 88 03 46 41 4f 75 ca 90 00 } //00 00 
		$a_00_3 = {78 } //c3 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_SS_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 75 fc 03 f7 8a 03 88 45 fa 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fa 32 45 f9 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca } //02 00 
		$a_01_1 = {8b 75 fc 03 f7 8a 03 88 45 f9 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f9 32 45 fa 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 f9 88 06 47 43 49 75 ca } //01 00 
		$a_03_2 = {8b 75 fc 03 f7 8a 03 88 45 90 02 02 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 90 02 02 32 45 90 02 02 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 90 02 02 88 06 47 43 49 75 ca 90 00 } //00 00 
		$a_00_3 = {78 } //3f 01  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_SS_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {83 7d ec 00 76 36 8b 45 ec b9 05 00 00 00 33 d2 f7 f1 85 d2 75 15 8b 45 ec 8a 80 a8 3e 46 00 34 4f 8b 55 fc 03 55 ec 88 02 eb 11 8b 45 ec 8a 80 a8 3e 46 00 8b 55 fc 03 55 ec 88 02 ff 45 ec 81 7d ec 21 80 00 00 75 b8 } //02 00 
		$a_00_1 = {83 7d e8 00 76 36 8b 45 e8 b9 05 00 00 00 33 d2 f7 f1 85 d2 75 15 8b 45 e8 8a 80 4c af 46 00 34 99 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 4c af 46 00 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 24 8b 00 00 75 b8 } //01 00 
		$a_02_2 = {76 36 8b 45 90 02 04 b9 05 00 00 00 33 d2 f7 f1 85 d2 75 15 8b 45 90 02 04 8a 80 4c af 46 00 34 99 8b 55 fc 03 55 90 02 04 88 02 eb 11 8b 45 90 02 04 8a 80 4c af 46 00 8b 55 fc 03 55 90 02 04 88 02 ff 45 90 02 04 81 7d 90 02 04 90 02 08 75 b8 90 00 } //02 00 
		$a_03_3 = {83 7d e8 00 76 36 8b 45 e8 90 02 15 75 15 8b 45 e8 8a 80 90 02 06 34 90 01 01 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 90 1b 01 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 90 02 06 75 b8 90 00 } //00 00 
		$a_00_4 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_SS_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 7d fc 00 76 34 8b 45 fc bf 05 00 00 00 33 d2 f7 f7 85 d2 75 14 8a 01 34 7c 8b d3 03 55 fc 73 05 e8 36 72 f7 ff 88 02 eb 10 8b c3 03 45 fc 73 05 e8 26 72 f7 ff 8a 11 88 10 ff 45 fc 41 81 7d fc 67 92 00 00 75 b9 } //00 00 
	condition:
		any of ($a_*)
 
}