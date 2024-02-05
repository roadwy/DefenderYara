
rule Trojan_Win32_Glupteba_KMG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 d0 c1 e8 05 89 45 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 85 90 01 05 45 90 01 01 81 3d 90 01 04 12 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 44 24 90 01 02 44 24 90 01 01 81 3d 90 01 04 12 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 84 24 90 01 05 44 24 90 01 01 81 3d 90 01 04 12 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 02 45 90 01 01 8b 45 90 01 02 f0 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 02 45 fc 8b 45 90 01 01 8b df c1 e3 04 03 5d 90 01 02 c7 33 d8 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 0c 10 8b 0d 90 01 04 40 3b c1 72 90 00 } //01 00 
		$a_02_1 = {c1 e8 05 89 45 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 85 90 01 04 01 45 90 01 01 81 3d 90 01 04 12 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 75 05 0f 00 8b 1d 90 01 04 01 45 90 01 02 5d 90 01 01 8b 45 90 01 01 8a 14 08 a1 90 01 04 88 14 08 90 00 } //01 00 
		$a_02_1 = {30 04 16 42 3b d7 7c 90 09 05 00 e8 6b ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e0 04 03 45 90 01 01 c7 05 90 01 04 36 06 ea e9 33 45 90 01 01 33 c1 2b f0 8b de c1 e3 04 81 3d 90 01 04 8c 07 00 00 89 45 90 01 01 75 90 00 } //01 00 
		$a_02_1 = {c1 e9 05 89 4d 90 01 01 8b 45 90 01 04 c7 05 90 01 04 36 06 ea e9 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 33 45 90 00 } //01 00 
		$a_02_2 = {33 c1 2b f8 8b f7 c1 e6 04 81 3d 90 01 04 8c 07 00 00 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}