
rule Trojan_Win32_Redline_MKYY_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 25 ?? ?? ?? ?? ?? 8d 14 01 8b c8 c1 e1 ?? 03 4d ?? c1 e8 ?? 33 ca 03 c3 33 c1 89 55 ?? 89 4d ?? 89 45 ?? 8b 45 ?? 01 05 } //1
		$a_03_1 = {01 45 fc 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}