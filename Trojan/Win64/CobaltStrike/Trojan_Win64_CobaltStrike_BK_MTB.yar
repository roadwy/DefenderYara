
rule Trojan_Win64_CobaltStrike_BK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c3 4d 8d 40 90 01 01 48 f7 e1 41 ff c2 48 c1 ea 90 01 01 48 6b c2 90 01 01 48 2b c8 0f b6 44 8c 90 01 01 41 30 40 90 01 01 49 63 ca 48 81 f9 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f2 0f 11 44 24 90 01 01 66 90 01 08 fe 4c 15 90 01 01 33 c0 0f b6 4c 15 90 01 01 48 90 01 03 49 90 01 03 49 90 01 03 41 90 01 02 32 4c 04 90 01 01 4c 8d 48 90 01 01 88 8c 15 90 01 04 41 90 01 06 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BK_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {c1 c9 08 e8 90 02 04 41 0f b6 0c 3c 31 c1 41 33 0e 49 ff c5 41 89 4e 20 49 83 fd 08 75 06 48 ff c7 45 31 ed 49 83 c6 04 4c 39 f5 75 90 00 } //02 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 } //00 00  cmd /c C:\Windows\Temp
	condition:
		any of ($a_*)
 
}