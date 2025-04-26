
rule Trojan_Win32_Redline_MKWW_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? c7 85 } //1
		$a_03_1 = {c1 ea 05 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}