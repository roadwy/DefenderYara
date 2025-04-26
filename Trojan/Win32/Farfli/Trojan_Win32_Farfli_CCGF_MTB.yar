
rule Trojan_Win32_Farfli_CCGF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d3 0f 28 05 ?? ?? ?? ?? 6a 18 0f 11 45 c8 c7 45 ?? 63 2f 2f 44 c7 45 ?? 6f 63 75 6d c7 45 ?? 65 6e 74 73 66 c7 45 ?? 2f 2f c6 45 e6 00 ff d3 } //1
		$a_01_1 = {68 f8 f5 40 00 68 70 f6 40 00 68 80 f6 40 00 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}