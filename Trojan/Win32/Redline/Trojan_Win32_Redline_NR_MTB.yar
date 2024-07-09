
rule Trojan_Win32_Redline_NR_MTB{
	meta:
		description = "Trojan:Win32/Redline.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea ?? 03 55 e4 c1 e0 ?? 03 45 d4 89 4d f4 33 d0 33 d1 89 55 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 ?? 03 45 d8 89 45 f0 8b 45 08 03 45 e8 89 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}