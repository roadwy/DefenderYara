
rule Trojan_Win32_Redline_GJU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f 90 01 01 47 e2 90 00 } //0a 00 
		$a_03_1 = {d1 f9 0f b6 95 90 01 04 c1 e2 07 0b ca 88 8d 90 01 04 0f b6 85 90 01 04 f7 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GJU_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_1 = {79 78 76 78 73 69 77 76 6f 73 } //01 00  yxvxsiwvos
		$a_01_2 = {72 6a 6c 64 6f 76 70 76 74 6d 6f 61 68 64 75 64 } //01 00  rjldovpvtmoahdud
		$a_01_3 = {65 69 6b 68 71 71 72 79 71 67 62 66 61 74 } //01 00  eikhqqryqgbfat
		$a_01_4 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //00 00  SystemFunction036
	condition:
		any of ($a_*)
 
}