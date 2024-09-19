
rule Trojan_Win32_Zenpak_RE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f0 07 31 35 ?? ?? ?? ?? 4a 89 d0 42 8d 05 ?? ?? ?? ?? 89 38 8d 05 ?? ?? ?? ?? 01 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 d1 e9 ba 93 24 49 92 89 [0-06] 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b [0-06] 29 c1 89 c8 83 e8 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 03 8d 05 ?? ?? ?? ?? 31 18 40 40 83 f0 03 8d 05 ?? ?? ?? ?? 01 30 ba 05 00 00 00 83 f0 04 31 d0 8d 05 ?? ?? ?? ?? 89 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 1e 8b 7d e4 8b 5d d0 32 0c 1f 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 32 28 00 00 8b 55 e0 88 0c 1a c7 05 ?? ?? ?? ?? f4 04 00 00 8b 4d cc 8b 55 f0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}