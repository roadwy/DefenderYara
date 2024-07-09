
rule Trojan_Win32_Redline_MKIK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8d 14 06 c1 e1 ?? 03 4d ?? c1 e8 ?? 03 45 ?? 33 ca 33 c1 89 4d ?? 89 45 ?? 8b 45 ?? 01 05 } //1
		$a_03_1 = {01 45 fc 83 6d ?? ?? 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}