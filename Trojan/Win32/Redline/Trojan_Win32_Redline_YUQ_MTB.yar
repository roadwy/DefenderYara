
rule Trojan_Win32_Redline_YUQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.YUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 08 83 c5 90 0a 18 00 81 45 ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d } //1
		$a_03_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 03 fe 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 6a ?? ff 15 fc 10 40 00 83 0d ?? ?? ?? ?? ?? 31 7d ?? 8b c6 c1 e8 ?? 03 45 ?? c7 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}