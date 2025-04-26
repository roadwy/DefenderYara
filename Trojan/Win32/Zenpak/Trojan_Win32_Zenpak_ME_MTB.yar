
rule Trojan_Win32_Zenpak_ME_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 b9 ab aa aa aa 89 45 ec f7 e1 c1 ea 03 6b c2 0c 8b 4d ec 29 c1 89 c8 83 e8 04 89 4d d8 89 45 d4 74 86 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}