
rule Trojan_Win32_Zusy_BU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 69 6f 65 73 67 75 69 6f 73 65 67 68 65 61 73 69 75 67 } //02 00  Bioesguiosegheasiug
		$a_01_1 = {4a 4b 6b 61 65 6a 67 66 69 73 65 6a 69 6f 65 67 6f 73 65 6a 69 } //02 00  JKkaejgfisejioegoseji
		$a_01_2 = {6f 73 69 64 66 67 69 75 6f 65 77 73 67 6f 69 65 77 6a 67 68 69 65 } //01 00  osidfgiuoewsgoiewjghie
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}