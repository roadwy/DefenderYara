
rule Trojan_Win32_Redline_NEBB_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {76 1f 8b 0d ?? ?? ?? 00 8a 94 01 1b 1b 01 00 8b 0d ?? ?? ?? 00 88 14 01 40 3b 05 ?? ?? ?? 00 72 e1 } //10
		$a_01_1 = {89 44 24 20 8b 4c 24 18 8b d6 d3 ea 03 54 24 30 89 54 24 14 8b 44 24 20 31 44 24 10 8b 44 24 10 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}