
rule Trojan_Win32_Stresid_C{
	meta:
		description = "Trojan:Win32/Stresid.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {88 84 28 f4 fe ff ff } //1
		$a_01_1 = {8a 9c 29 f4 fe ff ff } //1
		$a_01_2 = {8a 94 28 f4 fe ff ff } //1
		$a_01_3 = {8d 8c 29 f4 fe ff ff } //1
		$a_01_4 = {02 08 0f b6 c1 } //1
		$a_03_5 = {8a 84 28 f4 fe ff ff 90 18 32 04 3e 90 18 88 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}