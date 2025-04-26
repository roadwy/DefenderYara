
rule Trojan_Win32_Alureon_EP{
	meta:
		description = "Trojan:Win32/Alureon.EP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f8 21 43 65 87 c7 45 e8 2b 02 00 00 } //1
		$a_03_1 = {ff d0 c6 85 ?? ?? ?? ?? e9 c7 85 } //1
		$a_01_2 = {6d 00 61 00 78 00 73 00 73 00 63 00 6f 00 72 00 65 00 } //1 maxsscore
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}