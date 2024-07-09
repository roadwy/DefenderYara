
rule Trojan_Win32_Zenpak_ASK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d ?? 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45 ?? 0f 84 } //1
		$a_03_1 = {29 d0 31 3d [0-04] 83 f0 09 29 d0 83 c0 02 89 d0 01 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}