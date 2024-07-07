
rule Trojan_Win32_Emotet_K_MTB{
	meta:
		description = "Trojan:Win32/Emotet.K!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 64 76 61 6e 63 65 20 46 69 6c 65 20 53 70 6c 69 74 74 65 72 5c 6d 73 70 } //1 Software\Advance File Splitter\msp
		$a_01_1 = {6d 73 70 5f 67 65 72 6d 61 6e 2e 64 6c 6c } //1 msp_german.dll
		$a_01_2 = {6d 73 70 5f 73 70 61 6e 69 73 68 2e 64 6c 6c } //1 msp_spanish.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}