
rule Trojan_Win32_AveMariaRat_MD_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 65 6a 67 6b 67 75 69 63 } //01 00  vejgkguic
		$a_01_1 = {72 77 65 61 79 7a 7a 75 2e 64 6c 6c } //01 00  rweayzzu.dll
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 68 65 61 72 74 62 72 65 61 6b 65 72 } //01 00  SOFTWARE\heartbreaker
		$a_01_3 = {63 6f 62 72 61 5c 65 6d 62 61 72 72 61 73 73 65 73 5c 66 72 61 63 74 75 72 65 73 2e 6a 70 67 } //01 00  cobra\embarrasses\fractures.jpg
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {57 72 69 74 65 46 69 6c 65 } //00 00  WriteFile
	condition:
		any of ($a_*)
 
}