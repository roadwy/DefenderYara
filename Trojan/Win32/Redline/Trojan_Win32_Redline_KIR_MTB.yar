
rule Trojan_Win32_Redline_KIR_MTB{
	meta:
		description = "Trojan:Win32/Redline.KIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08 } //1
		$a_03_1 = {c1 e8 05 03 45 ?? 03 f2 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 ?? 8b 45 ?? 29 45 fc 89 7d f8 8b 45 ?? 01 45 f8 2b 5d f8 ff 4d ?? 89 5d ?? 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}