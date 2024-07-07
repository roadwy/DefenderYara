
rule Trojan_Win32_Emotet_AF_MSR{
	meta:
		description = "Trojan:Win32/Emotet.AF!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 66 78 43 6f 6e 74 72 6f 6c 42 61 72 37 30 73 } //1 AfxControlBar70s
		$a_01_1 = {41 66 78 4d 44 49 46 72 61 6d 65 37 30 73 } //1 AfxMDIFrame70s
		$a_01_2 = {41 66 78 46 72 61 6d 65 4f 72 56 69 65 77 37 30 73 } //1 AfxFrameOrView70s
		$a_01_3 = {70 61 62 6c 6f 76 61 6e 64 65 72 6d 65 65 72 2e 6e 6c } //1 pablovandermeer.nl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}