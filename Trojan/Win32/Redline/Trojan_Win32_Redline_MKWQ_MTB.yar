
rule Trojan_Win32_Redline_MKWQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? 03 55 ?? 89 55 } //1
		$a_03_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}