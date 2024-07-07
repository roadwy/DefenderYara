
rule Trojan_Win32_Zenpak_AL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 b9 ab aa aa aa 89 45 ec f7 e1 c1 ea 03 6b c2 0c 8b 4d ec 29 c1 89 c8 83 e8 05 89 4d e8 89 45 e4 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}