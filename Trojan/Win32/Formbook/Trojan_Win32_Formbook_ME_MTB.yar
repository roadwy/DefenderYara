
rule Trojan_Win32_Formbook_ME_MTB{
	meta:
		description = "Trojan:Win32/Formbook.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 8b 0c 10 51 ff 15 90 0a 2d 00 a3 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 ba 04 00 00 00 c1 e2 } //1
		$a_01_1 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_2 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //1 OutputDebugStringW
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4c 6f 63 6b 52 65 71 75 65 73 74 46 69 6c 65 } //1 InternetLockRequestFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}