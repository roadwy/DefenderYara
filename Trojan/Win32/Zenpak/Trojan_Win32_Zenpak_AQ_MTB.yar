
rule Trojan_Win32_Zenpak_AQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_AQ_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 6d 78 29 cc 89 44 24 64 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 64 29 c1 89 c8 83 e8 0d 89 4c 24 60 89 44 24 5c 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}