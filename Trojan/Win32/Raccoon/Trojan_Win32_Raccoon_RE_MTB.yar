
rule Trojan_Win32_Raccoon_RE_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb b2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {af 9e 1b 2c c7 44 24 90 01 01 30 2e 52 49 c7 84 24 90 01 01 00 00 00 7a cd 12 6e c7 84 24 90 01 04 c5 53 ef 46 b8 64 cb bc 3b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 83 65 fc 00 8b 45 0c 90 02 02 01 45 fc 8b 45 08 8b 4d 0c 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 4c 24 2c 89 35 90 01 04 31 4c 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 40 29 44 24 18 90 00 } //01 00 
		$a_03_1 = {81 01 e1 34 ef c6 c3 90 02 15 01 11 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //01 00  wallet.dat
		$a_01_1 = {6d 00 6f 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 } //01 00  mozzzzzzzzzzz
		$a_01_2 = {73 73 74 6d 6e 66 6f 5f } //01 00  sstmnfo_
		$a_03_3 = {40 8a 0c 85 90 01 04 8b 45 08 32 0c 03 a1 90 01 04 88 0c 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_7{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 01 08 c3 } //01 00 
		$a_03_1 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 04 ee 3d ea f4 90 02 d5 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 55 90 01 01 8b 4d 90 01 01 8b c2 d3 e0 90 02 20 d3 ea 8b 4d 90 01 01 8d 45 90 02 10 8b 45 90 01 01 33 90 01 01 31 45 90 01 01 89 90 01 05 8b 45 90 02 10 29 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RE_MTB_8{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 90 01 01 08 c3 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 90 02 15 56 c6 05 90 01 04 69 c6 05 90 01 04 72 c6 05 90 01 04 50 c6 05 90 01 04 74 c6 05 90 01 04 00 c6 05 90 01 04 74 c6 05 90 01 04 75 c6 05 90 01 04 61 c6 05 90 01 04 6c c6 05 90 01 04 72 c6 05 90 01 04 6f c6 05 90 01 04 74 c6 05 90 01 04 65 c6 05 90 01 04 63 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}