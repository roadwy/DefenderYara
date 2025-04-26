
rule Trojan_Win32_Redline_MBV_MTB{
	meta:
		description = "Trojan:Win32/Redline.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 03 8b 0c 87 8a 04 06 30 81 } //1
		$a_03_1 = {47 89 7c 24 14 81 ff ?? ?? ?? ?? 7d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}