
rule Trojan_Win32_Fareit_PD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 00 50 00 4f 00 72 00 41 00 20 00 68 00 4f 00 46 00 54 00 77 00 61 00 52 00 45 00 20 00 69 00 73 00 45 00 } //1 IPOrA hOFTwaRE isE
		$a_01_1 = {69 00 53 00 54 00 4f 00 6e 00 53 00 4f 00 46 00 74 00 20 00 6c 00 74 00 45 00 2e 00 } //1 iSTOnSOFt ltE.
		$a_01_2 = {63 00 41 00 53 00 54 00 70 00 41 00 53 00 53 00 } //1 cASTpASS
		$a_01_3 = {6f 00 4d 00 53 00 49 00 73 00 4f 00 46 00 54 00 20 00 49 00 6d 00 62 00 41 00 } //1 oMSIsOFT ImbA
		$a_01_4 = {6b 00 41 00 56 00 41 00 73 00 6f 00 46 00 54 00 } //1 kAVAsoFT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}