
rule Trojan_Win32_Emotet_GD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b c8 0f af cb 8d 04 7f 03 d1 2b d0 8b 44 24 90 01 01 8a 18 8a 0c 32 32 d9 8b 4c 24 90 01 01 88 18 8b 44 24 90 01 01 40 3b c1 89 44 24 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 03 c2 99 f7 fb 0f b6 44 14 90 01 01 32 44 2e 90 01 01 83 6c 24 90 02 10 88 46 90 00 } //01 00 
		$a_81_1 = {6e 56 63 68 6d 4a 68 77 52 52 25 21 40 4a 69 7a 4f 39 72 5a 6d 43 4a 54 55 6f 6b 24 58 35 54 26 33 4f 40 48 65 63 75 31 34 41 4a 21 70 68 52 68 59 6a } //00 00  nVchmJhwRR%!@JizO9rZmCJTUok$X5T&3O@Hecu14AJ!phRhYj
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {33 db 57 53 90 02 0f c6 90 02 03 6b c6 90 02 03 65 c6 90 02 03 72 c6 90 02 03 6e c6 90 02 03 65 c6 90 02 03 6c c6 90 02 03 33 c6 90 02 03 32 c6 90 02 03 2e c6 90 02 03 64 c6 90 02 03 6c c6 90 02 03 6c 90 02 0f ff 90 00 } //02 00 
		$a_02_1 = {ff d6 33 f6 90 02 0c c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 90 02 0f ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}