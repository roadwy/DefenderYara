
rule Trojan_Win32_Zenpak_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 6b c2 ?? 8b 4d ?? 29 c1 89 c8 83 e8 08 89 4d ?? 89 45 ?? 74 } //1
		$a_03_1 = {f7 e1 c1 ea 02 6b c2 ?? 8b 4d ec 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45 ?? 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}