
rule Trojan_Win32_Redline_JN_MTB{
	meta:
		description = "Trojan:Win32/Redline.JN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 89 54 24 ?? 89 0c 24 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24 } //1
		$a_03_1 = {d3 e6 89 5c 24 ?? 03 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b d7 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 8b ce e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}